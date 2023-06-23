use crate::backends::storage_backend::StorageBackend;
use crate::data_server::cors::*;
use crate::data_server::utils::buffered_s3_sink::BufferedS3Sink;
use anyhow::Result;
use aruna_file::helpers::footer_parser::FooterParser;
use aruna_file::streamreadwrite::ArunaStreamReadWriter;
use aruna_file::transformers::async_sender_sink::AsyncSenderSink;
use aruna_file::transformers::compressor::ZstdEnc;
use aruna_file::transformers::decompressor::ZstdDec;
use aruna_file::transformers::decrypt::ChaCha20Dec;
use aruna_file::transformers::encrypt::ChaCha20Enc;
use aruna_file::transformers::filter::Filter;
use aruna_file::transformers::footer::FooterGenerator;
use aruna_rust_api::api::internal::v1::internal_authorize_service_client::InternalAuthorizeServiceClient;
use aruna_rust_api::api::internal::v1::Authorization;
use aruna_rust_api::api::internal::v1::FinalizeObjectRequest;
use aruna_rust_api::api::internal::v1::GetCollectionByBucketRequest;
use aruna_rust_api::api::internal::v1::GetObjectLocationRequest;
use aruna_rust_api::api::internal::v1::GetOrCreateEncryptionKeyRequest;
use aruna_rust_api::api::internal::v1::GetTokenFromSecretRequest;
use aruna_rust_api::api::internal::v1::Location as ArunaLocation;
use aruna_rust_api::api::internal::v1::PartETag;
use aruna_rust_api::api::storage::models::v1::Hash;
use aruna_rust_api::api::storage::models::v1::Hashalgorithm;
use aruna_rust_api::api::storage::models::v1::KeyValue;
use aruna_rust_api::api::storage::services::v1::collection_service_client;
use aruna_rust_api::api::storage::services::v1::object_service_client;
use aruna_rust_api::api::storage::services::v1::GetCollectionByIdRequest;
use aruna_rust_api::api::storage::services::v1::GetObjectsAsListV2Request;
use aruna_rust_api::api::storage::services::v1::UpdateCollectionRequest;
use futures::StreamExt;
use futures::TryStreamExt;
use http::HeaderMap;
use md5::{Digest, Md5};
use s3s::dto::*;
use s3s::s3_error;
use s3s::S3Error;
use s3s::S3Request;
use s3s::S3Response;
use s3s::S3Result;
use s3s::S3;
use sha2::Sha256;
use std::sync::Arc;

use super::data_handler::DataHandler;
use super::utils::aruna_notifier::ArunaNotifier;
use super::utils::buffered_s3_sink::parse_notes_get_etag;
use super::utils::ranges::calculate_content_length_from_range;
use super::utils::ranges::calculate_ranges;
use super::utils::user_client;
use crate::data_server::utils::utils::create_location_from_hash;

#[derive(Debug)]
pub struct S3ServiceServer {
    backend: Arc<Box<dyn StorageBackend>>,
    data_handler: Arc<DataHandler>,
    aruna_external: String,
    aruna_internal: String,
}

impl S3ServiceServer {
    pub async fn new(
        backend: Arc<Box<dyn StorageBackend>>,
        data_handler: Arc<DataHandler>,
        aruna_external: String,
        aruna_internal: String,
    ) -> Result<Self> {
        Ok(S3ServiceServer {
            backend: backend.clone(),
            data_handler,
            aruna_external,
            aruna_internal,
        })
    }
}

#[async_trait::async_trait]
impl S3 for S3ServiceServer {
    #[tracing::instrument]
    async fn put_object(
        &self,
        req: S3Request<PutObjectInput>,
    ) -> S3Result<S3Response<PutObjectOutput>> {
        let content_length = match req.input.content_length {
            Some(content_length) if content_length > 0 => content_length,
            _ => {
                return Err(s3_error!(
                    MissingContentLength,
                    "Missing or invalid (0) content-length"
                ));
            }
        };

        let mut anotif = ArunaNotifier::new(
            self.data_handler.internal_notifier_service.clone(),
            self.data_handler.settings.clone(),
        );
        anotif.set_credentials(req.credentials)?;
        anotif
            .get_or_create_object(&req.input.bucket, &req.input.key, content_length)
            .await?;
        anotif.validate_hashes(req.input.content_md5, req.input.checksum_sha256)?;
        anotif.get_encryption_key().await?;

        let hash = anotif.get_sha256();

        let exists = match hash {
            Some(h) => {
                if !h.is_empty() && h.len() == 32 {
                    self.backend
                        .head_object(ArunaLocation {
                            bucket: format!("b{}", &h[0..2]),
                            path: h[2..].to_string(),
                            ..Default::default()
                        })
                        .await
                        .is_ok()
                } else {
                    false
                }
            }
            None => false,
        };

        let (location, is_temp) = anotif.get_location(exists)?;

        let mut md5_hash = Md5::new();
        let mut sha256_hash = Sha256::new();
        let mut final_md5 = String::new();
        let mut final_sha256 = String::new();
        let mut size_counter = 0;
        // If the object exists and the signatures match -> Skip the download

        if !exists {
            match req.input.body {
                Some(data) => {
                    // MD5 Stream
                    let md5ed_stream = data.inspect_ok(|bytes| md5_hash.update(bytes.as_ref()));
                    // Sha256 stream
                    let shaed_stream =
                        md5ed_stream.inspect_ok(|bytes| sha256_hash.update(bytes.as_ref()));

                    let sized_stream = shaed_stream.inspect_ok(|by| size_counter += by.len());

                    let mut awr = ArunaStreamReadWriter::new_with_sink(
                        sized_stream,
                        BufferedS3Sink::new(
                            self.backend.clone(),
                            location.clone(),
                            None,
                            None,
                            false,
                            None,
                        ),
                    );

                    if location.is_encrypted {
                        awr = awr.add_transformer(
                            ChaCha20Enc::new(true, anotif.retrieve_enc_key()?).map_err(|e| {
                                log::error!("{}", e);
                                s3_error!(
                                    InternalError,
                                    "Internal data transformer encryption error"
                                )
                            })?,
                        );
                    }

                    if location.is_compressed {
                        if content_length > 5242880 + 80 * 28 {
                            awr = awr.add_transformer(FooterGenerator::new(None, true))
                        }
                        awr = awr.add_transformer(ZstdEnc::new(0, true));
                    }

                    awr.process().await.map_err(|e| {
                        log::error!("{}", e);
                        s3_error!(InternalError, "Internal data transformer processing error")
                    })?;

                    if size_counter as i64 != content_length {
                        self.backend.delete_object(location).await.map_err(|e| {
                            log::error!(
                                "PUT: Unable to delete object, after wrong content_len: {}",
                                e
                            );
                            s3_error!(InternalError, "PUT: Unable to delete object")
                        })?;
                        return Err(s3_error!(
                            UnexpectedContent,
                            "Content length does not match"
                        ));
                    }
                }
                None => {
                    return Err(s3_error!(
                        InvalidObjectState,
                        "Request body / data is required, use ArunaAPI for empty objects"
                    ))
                }
            }

            final_md5 = format!("{:x}", md5_hash.finalize());
            final_sha256 = format!("{:x}", sha256_hash.finalize());

            let hashes_is_ok = anotif.test_final_hashes(&final_md5, &final_sha256)?;

            if !hashes_is_ok {
                self.backend.delete_object(location).await.map_err(|e| {
                    log::error!("PUT: Unable to delete object, after wrong hash: {}", e);
                    s3_error!(InternalError, "PUT: Unable to delete object")
                })?;
                return Err(s3_error!(InvalidDigest, "Invalid hash digest"));
            };
            if is_temp {
                let (object_id, collection_id) = anotif.get_col_obj()?;
                self.data_handler
                    .clone()
                    .move_encode(
                        location.clone(),
                        create_location_from_hash(
                            &final_sha256,
                            &object_id,
                            &collection_id,
                            self.data_handler.settings.encrypting,
                            self.data_handler.settings.compressing,
                            location.encryption_key.clone(),
                            self.data_handler.settings.endpoint_id.to_string(),
                            exists,
                        )
                        .0,
                        object_id,
                        collection_id,
                        Some(vec![
                            Hash {
                                alg: Hashalgorithm::Md5 as i32,
                                hash: final_md5.clone(),
                            },
                            Hash {
                                alg: Hashalgorithm::Sha256 as i32,
                                hash: final_sha256.clone(),
                            },
                        ]),
                        format!("s3://{}/{}", &req.input.bucket, &req.input.key),
                    )
                    .await
                    .map_err(|e| {
                        log::error!("InternalError: {}", e);
                        s3_error!(InternalError, "Internal data mover error")
                    })?
            }
        }

        if !is_temp {
            let (object_id, collection_id) = anotif.get_col_obj()?;
            self.data_handler
                .internal_notifier_service
                .clone() // This uses mpsc channel internally and just clones the handle -> Should be ok to clone
                .finalize_object(FinalizeObjectRequest {
                    object_id,
                    collection_id,
                    location: Some(location),
                    content_length,
                    hashes: vec![
                        Hash {
                            alg: Hashalgorithm::Md5 as i32,
                            hash: final_md5,
                        },
                        Hash {
                            alg: Hashalgorithm::Sha256 as i32,
                            hash: final_sha256.to_string(),
                        },
                    ],
                })
                .await
                .map_err(|e| {
                    log::error!("{}", e);
                    s3_error!(InternalError, "Internal aruna error")
                })?;
        }

        let (object_id, _) = anotif.get_col_obj()?;
        let output = PutObjectOutput {
            e_tag: Some(format!("-{}", object_id)),
            checksum_sha256: Some(final_sha256),
            ..Default::default()
        };
        Ok(S3Response::new(output))
    }

    #[tracing::instrument]
    async fn create_multipart_upload(
        &self,
        req: S3Request<CreateMultipartUploadInput>,
    ) -> S3Result<S3Response<CreateMultipartUploadOutput>> {
        let mut anotif = ArunaNotifier::new(
            self.data_handler.internal_notifier_service.clone(),
            self.data_handler.settings.clone(),
        );
        anotif.set_credentials(req.credentials)?;
        anotif
            .get_or_create_object(&req.input.bucket, &req.input.key, 0)
            .await?;

        let (object_id, collection_id) = anotif.get_col_obj()?;

        let init_response = self
            .backend
            .clone()
            .init_multipart_upload(ArunaLocation {
                bucket: "temp".to_string(),
                path: format!("{}/{}", collection_id, object_id),
                ..Default::default()
            })
            .await
            .map_err(|e| {
                log::error!("{}", e);
                s3_error!(InvalidArgument, "Unable to initialize multi-part")
            })?;

        Ok(S3Response::new(CreateMultipartUploadOutput {
            key: Some(req.input.key),
            bucket: Some(req.input.bucket),
            upload_id: Some(init_response),
            ..Default::default()
        }))
    }

    #[tracing::instrument]
    async fn upload_part(
        &self,
        req: S3Request<UploadPartInput>,
    ) -> S3Result<S3Response<UploadPartOutput>> {
        // Why?
        // let content_length =
        match req.input.content_length {
            Some(content_length) => content_length,
            None => {
                return Err(s3_error!(
                    MissingContentLength,
                    "Missing or invalid (0) content-length"
                ));
            }
        };
        let mut anotif = ArunaNotifier::new(
            self.data_handler.internal_notifier_service.clone(),
            self.data_handler.settings.clone(),
        );
        anotif.set_credentials(req.credentials)?;
        anotif
            .get_or_create_object(&req.input.bucket, &req.input.key, 0)
            .await?;

        anotif.get_encryption_key().await?;

        let (object_id, collection_id) = anotif.get_col_obj()?;
        let etag;

        match req.input.body {
            Some(data) => {
                let mut awr = ArunaStreamReadWriter::new_with_sink(
                    data.into_stream(),
                    BufferedS3Sink::new(
                        self.backend.clone(),
                        ArunaLocation {
                            bucket: "temp".to_string(),
                            path: format!("{}/{}", collection_id, object_id),
                            ..Default::default()
                        },
                        Some(req.input.upload_id),
                        Some(req.input.part_number),
                        true,
                        None,
                    ),
                );

                if self.data_handler.settings.encrypting {
                    awr = awr.add_transformer(
                        ChaCha20Enc::new(true, anotif.retrieve_enc_key()?).map_err(|e| {
                            log::error!("{}", e);
                            s3_error!(InternalError, "Internal data transformer encryption error")
                        })?,
                    );
                }

                awr.process().await.map_err(|e| {
                    log::error!("Processing error: {}", e);
                    s3_error!(InternalError, "Internal data transformer processing error")
                })?;

                etag = parse_notes_get_etag(awr.query_notifications().await.map_err(|e| {
                    log::error!("Processing error: {}", e);
                    s3_error!(InternalError, "ETagError")
                })?)
                .map_err(|e| {
                    log::error!("Processing error: {}", e);
                    s3_error!(InternalError, "ETagError")
                })?;
            }
            _ => return Err(s3_error!(InvalidPart, "MultiPart cannot be empty")),
        };

        Ok(S3Response::new(UploadPartOutput {
            e_tag: Some(format!("-{}", etag)),
            ..Default::default()
        }))
    }

    #[tracing::instrument]
    async fn complete_multipart_upload(
        &self,
        req: S3Request<CompleteMultipartUploadInput>,
    ) -> S3Result<S3Response<CompleteMultipartUploadOutput>> {
        let mut anotif = ArunaNotifier::new(
            self.data_handler.internal_notifier_service.clone(),
            self.data_handler.settings.clone(),
        );
        anotif.set_credentials(req.credentials)?;
        anotif
            .get_or_create_object(&req.input.bucket, &req.input.key, 0)
            .await?;

        let parts = match req.input.multipart_upload {
            Some(parts) => parts
                .parts
                .ok_or_else(|| s3_error!(InvalidPart, "Parts must be specified")),
            None => return Err(s3_error!(InvalidPart, "Parts must be specified")),
        }?;

        let etag_parts = parts
            .into_iter()
            .map(|a| {
                Ok(PartETag {
                    part_number: a.part_number as i64,
                    etag: a
                        .e_tag
                        .ok_or_else(|| s3_error!(InvalidPart, "etag must be specified"))?,
                })
            })
            .collect::<Result<Vec<PartETag>, S3Error>>()?;

        let (object_id, collection_id) = anotif.get_col_obj()?;
        // Does this object exists (including object id etc)
        //req.input.multipart_upload.unwrap().
        self.data_handler
            .clone()
            .finish_multipart(
                etag_parts,
                object_id.to_string(),
                collection_id,
                req.input.upload_id,
                anotif.get_path()?,
            )
            .await?;

        Ok(S3Response::new(CompleteMultipartUploadOutput {
            e_tag: Some(object_id),
            version_id: Some(anotif.get_revision_string()?),
            ..Default::default()
        }))
    }

    async fn get_object(
        &self,
        req: S3Request<GetObjectInput>,
    ) -> S3Result<S3Response<GetObjectOutput>> {
        // Get the credentials
        dbg!(req.credentials.clone());
        let creds = match req.credentials {
            Some(cred) => cred,
            None => {
                log::error!("{}", "Not identified PutObjectRequest");
                return Err(s3_error!(NotSignedUp, "Your account is not signed up"));
            }
        };

        let rev_id = match req.input.version_id {
            Some(a) => a,
            None => String::new(),
        };

        let get_location_response = self
            .data_handler
            .internal_notifier_service
            .clone()
            .get_object_location(GetObjectLocationRequest {
                path: format!("s3://{}/{}", req.input.bucket, req.input.key),
                revision_id: rev_id,
                access_key: creds.access_key,
                endpoint_id: self.data_handler.settings.endpoint_id.to_string(),
            })
            .await
            .map_err(|_| s3_error!(NoSuchKey, "Key not found, getlocation"))?
            .into_inner();

        let cors: CORSVec = get_location_response.cors_configurations.into();

        let headers: Result<HeaderMap, S3Error> = cors.into();

        let _location = get_location_response
            .location
            .ok_or_else(|| s3_error!(NoSuchKey, "Key not found, location"))?;

        let object = get_location_response
            .object
            .clone()
            .ok_or_else(|| s3_error!(NoSuchKey, "Key not found, object"))?;

        let sha256_hash = object
            .hashes
            .iter()
            .find(|a| a.alg == Hashalgorithm::Sha256 as i32)
            .cloned()
            .ok_or_else(|| s3_error!(NoSuchKey, "Key not found"))?;

        if sha256_hash.hash.is_empty() {
            return Err(s3_error!(InternalError, "Aruna returned empty signature"));
        }

        let (internal_sender, internal_receiver) = async_channel::bounded(10);

        let processor_clone = self.backend.clone();

        let sha_clone = sha256_hash.hash.clone();

        let content_length = get_location_response
            .object
            .clone()
            .ok_or_else(|| s3_error!(NoSuchKey, "Key not found"))?
            .content_len;

        let get_location = ArunaLocation {
            bucket: format!("b{}", &sha256_hash.hash[0..2]),
            path: sha256_hash.hash[2..].to_string(),
            ..Default::default()
        };

        let setting = self.data_handler.settings.clone();

        let path = format!("s3://{}/{}", req.input.bucket, req.input.key);

        let encryption_key = self
            .data_handler
            .internal_notifier_service // This uses mpsc channel internally and just clones the handle -> Should be ok to clone
            .clone()
            .get_or_create_encryption_key(GetOrCreateEncryptionKeyRequest {
                path,
                endpoint_id: setting.endpoint_id.to_string(),
                hash: sha_clone,
            })
            .await
            .map_err(|e| {
                log::error!("{}", e);
                s3_error!(InternalError, "Internal notifier error")
            })?
            .into_inner()
            .encryption_key
            .as_bytes()
            .to_vec();

        let footer_parser = if content_length > (65536 + 28) * 2 {
            let (footer_sender, footer_receiver) = async_channel::unbounded();
            self.backend
                .get_object(
                    get_location.clone(),
                    Some(format!("bytes=-{}", (65536 + 28) * 2)),
                    footer_sender,
                )
                .await
                .map_err(|e| {
                    log::error!("{}", e);
                    s3_error!(InternalError, "Unable to get encryption_key")
                })?;

            let mut output = Vec::with_capacity(130_000);

            let mut arsw =
                ArunaStreamReadWriter::new_with_writer(footer_receiver.map(Ok), &mut output);

            arsw.process().await.map_err(|e| {
                log::error!("{}", e);
                s3_error!(InternalError, "Unable to get footer")
            })?;
            drop(arsw);

            match FooterParser::from_encrypted(
                &output
                    .try_into()
                    .map_err(|_| s3_error!(InternalError, "Unable to get encryption_key"))?,
                &encryption_key,
            ) {
                Ok(p) => Some(p),
                Err(_) => None,
            }
        } else {
            None
        };

        let (query_range, filter_ranges) =
            calculate_ranges(req.input.range, content_length as u64, footer_parser).map_err(
                |e| {
                    log::error!("{}", e);
                    s3_error!(InternalError, "Unable to build FooterParser")
                },
            )?;

        let calc_content_len = match filter_ranges {
            Some(r) => calculate_content_length_from_range(r),
            None => object.content_len,
        };

        tokio::spawn(async move {
            processor_clone
                .get_object(get_location, query_range, internal_sender)
                .await
        });

        let (final_sender, final_receiver) = async_channel::bounded(10);

        tokio::spawn(async move {
            let mut asrw = ArunaStreamReadWriter::new_with_sink(
                internal_receiver.map(Ok),
                AsyncSenderSink::new(final_sender),
            );

            if let Some(r) = filter_ranges {
                asrw = asrw.add_transformer(Filter::new(r));
            };

            asrw.add_transformer(ZstdDec::new())
                .add_transformer(ChaCha20Dec::new(encryption_key).map_err(|e| {
                    log::error!("{}", e);
                    s3_error!(InternalError, "Internal notifier error")
                })?)
                .process()
                .await
                .map_err(|e| {
                    log::error!("{}", e);
                    s3_error!(InternalError, "Internal notifier error")
                })?;

            match 1 {
                1 => Ok(()),
                _ => Err(s3_error!(InternalError, "Internal notifier error")),
            }
        });

        let timestamp = object
            .created
            .map(|e| {
                Timestamp::parse(
                    TimestampFormat::EpochSeconds,
                    format!("{}", e.seconds).as_str(),
                )
            })
            .ok_or_else(|| s3_error!(InternalError, "internal processing error"))?
            .map_err(|_| s3_error!(InternalError, "internal processing error"))?;

        let body =
            Some(StreamingBlob::wrap(final_receiver.map_err(|_| {
                s3_error!(InternalError, "internal processing error")
            })));

        let mut response = S3Response::new(GetObjectOutput {
            body,
            content_length: calc_content_len,
            last_modified: Some(timestamp),
            e_tag: Some(format!("-{}", object.id)),
            version_id: Some(format!("{}", object.rev_number)),
            ..Default::default()
        });

        response.headers =
            headers.map_err(|_| s3_error!(InternalError, "Internal parsing error"))?;

        Ok(response)
    }

    async fn put_bucket_cors(
        &self,
        req: S3Request<PutBucketCorsInput>,
    ) -> S3Result<S3Response<PutBucketCorsOutput>> {
        let mut auth_client = InternalAuthorizeServiceClient::connect(self.aruna_internal.clone())
            .await
            .map_err(|e| {
                log::error!("{}", e);
                s3_error!(InternalError, "Unable to connect to ArunaServer")
            })?;

        let credentials = req
            .credentials
            .ok_or_else(|| s3_error!(NotSignedUp, "Your account is not signed up"))?;

        let token = auth_client
            .get_token_from_secret(GetTokenFromSecretRequest {
                authorization: Some(Authorization {
                    secretkey: credentials.secret_key.expose().to_string(),
                    accesskey: credentials.access_key.clone(),
                }),
            })
            .await
            .map_err(|e| {
                log::error!("{}", e);
                s3_error!(NotSignedUp, "Your account is not signed up")
            })?
            .into_inner()
            .token;

        let cors: CORSVec = req.input.cors_configuration.cors_rules.into();

        let mut cors: Vec<KeyValue> = match cors.into() {
            Ok(cors) => cors,
            Err(e) => {
                log::debug!("{}", e);
                return Err(s3_error!(InternalError, "Error while parsing CORS headers"));
            }
        };

        let user_client = user_client::UserClient::new(self.aruna_external.clone(), token)
            .await
            .map_err(|e| {
                log::error!("{}", e);
                s3_error!(InternalError, "Unable to connect to endpoint")
            })?;

        let collection = self
            .data_handler
            .internal_notifier_service
            .clone()
            .get_collection_by_bucket(GetCollectionByBucketRequest {
                bucket: req.input.bucket,
                access_key: credentials.access_key,
            })
            .await
            .map_err(|e| {
                log::error!("{}", e);
                s3_error!(NoSuchBucket, "Bucket not found")
            })?
            .into_inner();

        let channel = user_client.endpoint.connect().await.map_err(|e| {
            log::error!("{}", e);
            s3_error!(InternalError, "Unable to connect to endpoint")
        })?;
        let mut client = collection_service_client::CollectionServiceClient::with_interceptor(
            channel,
            user_client.interceptor,
        );

        let mut collection = match client
            .get_collection_by_id(GetCollectionByIdRequest {
                collection_id: collection.collection_id.clone(),
            })
            .await
            .map_err(|e| {
                log::error!("{}", e);
                s3_error!(InternalError, "Unable to query collection info")
            })?
            .into_inner()
            .collection
        {
            Some(c) => c,
            None => {
                return Err(s3_error!(InternalError, "Unable to query collection info"));
            }
        };

        cors.append(&mut collection.labels);
        match client
            .update_collection(UpdateCollectionRequest {
                collection_id: collection.id,
                // This needs to be changed, but querying a collection would introduce an
                // additional unwanted request. Maybe we need a add_label_to_collection method?
                name: collection.name,
                labels: cors,
                description: collection.description,
                hooks: collection.hooks,
                label_ontology: collection.label_ontology,
                ..Default::default()
            })
            .await
        {
            Ok(_response) => Ok(S3Response::new(PutBucketCorsOutput {})),
            Err(err) => {
                log::error!("{}", err);
                Err(s3_error!(
                    InternalError,
                    "Internal error while updating CORS headers"
                ))
            }
        }
    }

    async fn get_bucket_cors(
        &self,
        req: S3Request<GetBucketCorsInput>,
    ) -> S3Result<S3Response<GetBucketCorsOutput>> {
        let mut auth_client = InternalAuthorizeServiceClient::connect(self.aruna_internal.clone())
            .await
            .map_err(|e| {
                log::error!("{}", e);
                s3_error!(InternalError, "Unable to connect to ArunaServer")
            })?;

        let credentials = req
            .credentials
            .ok_or_else(|| s3_error!(NotSignedUp, "Your account is not signed up"))?;

        let token = auth_client
            .get_token_from_secret(GetTokenFromSecretRequest {
                authorization: Some(Authorization {
                    secretkey: credentials.secret_key.expose().to_string(),
                    accesskey: credentials.access_key.clone(),
                }),
            })
            .await
            .map_err(|e| {
                log::error!("{}", e);
                s3_error!(NotSignedUp, "Your account is not signed up")
            })?
            .into_inner()
            .token;

        let user_client = user_client::UserClient::new(self.aruna_external.clone(), token)
            .await
            .map_err(|e| {
                log::error!("{}", e);
                s3_error!(InternalError, "Unable to connect to endpoint")
            })?;

        let collection = self
            .data_handler
            .internal_notifier_service
            .clone()
            .get_collection_by_bucket(GetCollectionByBucketRequest {
                bucket: req.input.bucket,
                access_key: credentials.access_key,
            })
            .await
            .map_err(|e| {
                log::error!("{}", e);
                s3_error!(NoSuchBucket, "Bucket not found")
            })?
            .into_inner();

        let channel = user_client.endpoint.connect().await.map_err(|e| {
            log::error!("{}", e);
            s3_error!(InternalError, "Unable to connect to endpoint")
        })?;
        let mut client = collection_service_client::CollectionServiceClient::with_interceptor(
            channel,
            user_client.interceptor,
        );

        let cors: Option<CORSVec> = match client
            .get_collection_by_id(GetCollectionByIdRequest {
                collection_id: collection.collection_id.clone(),
            })
            .await
            .map_err(|e| {
                log::error!("{}", e);
                s3_error!(InternalError, "Unable to query collection info")
            })?
            .into_inner()
            .collection
        {
            Some(c) => Some(c.labels.into()),
            None => None,
        };

        let cors: Option<Vec<CORSRule>> = match cors {
            Some(c) => Some(c.into()),
            None => None,
        };

        Ok(S3Response::new(GetBucketCorsOutput { cors_rules: cors }))
    }

    async fn head_object(
        &self,
        req: S3Request<HeadObjectInput>,
    ) -> S3Result<S3Response<HeadObjectOutput>> {
        // Get the credentials

        let creds = match req.credentials {
            Some(cred) => cred,
            None => {
                log::error!("{}", "Not identified PutObjectRequest");
                return Err(s3_error!(NotSignedUp, "Your account is not signed up"));
            }
        };

        let rev_id = match req.input.version_id {
            Some(a) => a,
            None => String::new(),
        };

        let get_location_response = self
            .data_handler
            .internal_notifier_service
            .clone()
            .get_object_location(GetObjectLocationRequest {
                // Soll auch die CORS header mitliefern aus der Collection
                path: format!("s3://{}/{}", req.input.bucket, req.input.key),
                revision_id: rev_id,
                access_key: creds.access_key,
                endpoint_id: self.data_handler.settings.endpoint_id.to_string(),
            })
            .await
            .map_err(|_| s3_error!(NoSuchKey, "Key not found, tag: head_get_loc"))?
            .into_inner();

        let _location = get_location_response
            .location
            .ok_or_else(|| s3_error!(NoSuchKey, "Key not found, tag: head_loc"))?;

        let object = get_location_response
            .object
            .ok_or_else(|| s3_error!(NoSuchKey, "Key not found, tag: head_obj"))?;

        let sha256_hash = object
            .hashes
            .iter()
            .find(|a| a.alg == Hashalgorithm::Sha256 as i32)
            .cloned()
            .ok_or_else(|| s3_error!(NoSuchKey, "Key not found, tag: head_sha"))?;

        let timestamp = object
            .created
            .map(|e| {
                Timestamp::parse(
                    TimestampFormat::EpochSeconds,
                    format!("{}", e.seconds).as_str(),
                )
            })
            .ok_or_else(|| s3_error!(InternalError, "internal processing error"))?
            .map_err(|_| s3_error!(InternalError, "internal processing error"))?;

        Ok(S3Response::new(HeadObjectOutput {
            content_length: object.content_len,
            last_modified: Some(timestamp),
            checksum_sha256: Some(sha256_hash.hash),
            e_tag: Some(object.id),
            version_id: Some(format!("{}", object.rev_number)),
            ..Default::default()
        }))
    }

    async fn list_objects(
        &self,
        _req: S3Request<ListObjectsInput>,
    ) -> S3Result<S3Response<ListObjectsOutput>> {
        Err(s3_error!(
            NotImplemented,
            "ListObjects is not implemented yet"
        ))
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<ListObjectsV2Input>,
    ) -> S3Result<S3Response<ListObjectsV2Output>> {
        let mut auth_client = InternalAuthorizeServiceClient::connect(self.aruna_internal.clone())
            .await
            .map_err(|e| {
                log::error!("{}", e);
                s3_error!(InternalError, "Unable to connect to ArunaServer")
            })?;

        let credentials = req
            .credentials
            .ok_or_else(|| s3_error!(NotSignedUp, "Your account is not signed up"))?;

        let token = auth_client
            .get_token_from_secret(GetTokenFromSecretRequest {
                authorization: Some(Authorization {
                    secretkey: credentials.secret_key.expose().to_string(),
                    accesskey: credentials.access_key.clone(),
                }),
            })
            .await
            .map_err(|e| {
                log::error!("{}", e);
                s3_error!(NotSignedUp, "Your account is not signed up")
            })?
            .into_inner()
            .token;

        let user_client = user_client::UserClient::new(self.aruna_external.clone(), token)
            .await
            .map_err(|e| {
                log::error!("{}", e);
                s3_error!(InternalError, "Unable to connect to endpoint")
            })?;

        let channel = user_client.endpoint.connect().await.map_err(|e| {
            log::error!("{}", e);
            s3_error!(InternalError, "Unable to connect to endpoint")
        })?;

        let mut client = object_service_client::ObjectServiceClient::with_interceptor(
            channel,
            user_client.interceptor,
        );

        let max_keys = match req.input.max_keys {
            Some(k) => Some(k as u32),
            None => None,
        };

        let response = client
            .get_objects_as_list_v2(GetObjectsAsListV2Request {
                bucket: req.input.bucket,
                continuation_token: req.input.continuation_token.clone(),
                delimiter: req.input.delimiter.clone(),
                max_keys,
                prefix: req.input.prefix.clone(),
                start_after: req.input.start_after.clone(),
            })
            .await
            .map_err(|e| {
                log::error!("{}", e);
                s3_error!(
                    InternalError,
                    "Error while requesting ListObjectsV2 from Server"
                )
            })?
            .into_inner();

        let common_prefixes = if response.prefixes.is_empty() {
            None
        } else {
            Some(
                response
                    .prefixes
                    .into_iter()
                    .map(|p| CommonPrefix {
                        prefix: Some(p.prefix),
                    })
                    .collect(),
            )
        };

        let contents = if response.contents.is_empty() {
            None
        } else {
            Some(
                response
                    .contents
                    .into_iter()
                    .map(|c| s3s::dto::Object {
                        checksum_algorithm: None,
                        e_tag: Some(c.id),
                        // This needs to be changed to path
                        key: Some(c.filename),
                        last_modified: None,
                        owner: None,
                        size: c.content_len,
                        // Needs to be parsed correctly
                        storage_class: None,
                    })
                    .collect(),
            )
        };
        Ok(S3Response::new(ListObjectsV2Output {
            name: Some(response.name),
            common_prefixes,
            continuation_token: req.input.continuation_token,
            next_continuation_token: response.next_continuation_token,
            delimiter: req.input.delimiter,
            start_after: req.input.start_after,
            encoding_type: None,
            key_count: response.key_count as i32,
            is_truncated: response.is_truncated,
            max_keys: response.max_keys as i32,
            prefix: req.input.prefix,
            contents,
        }))
    }

    async fn create_bucket(
        &self,
        _req: S3Request<CreateBucketInput>,
    ) -> S3Result<S3Response<CreateBucketOutput>> {
        Err(s3_error!(
            NotImplemented,
            "CreateBucket is not implemented yet"
        ))
    }
}
