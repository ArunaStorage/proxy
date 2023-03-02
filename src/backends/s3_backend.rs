use std::env;

use anyhow::anyhow;
use aruna_rust_api::api::internal::v1::{Location, PartETag, Range};
use async_channel::{Receiver, Sender};
use async_trait::async_trait;
use aws_sdk_s3::{
    model::{CompletedMultipartUpload, CompletedPart},
    types::ByteStream,
    Client, Region,
};
use tokio::io::{AsyncBufReadExt, BufReader};

use super::storage_backend::StorageBackend;

const S3_ENDPOINT_HOST_ENV_VAR: &str = "S3_ENDPOINT_HOST";

#[derive(Debug, Clone)]
pub struct S3Backend {
    pub s3_client: Client,
}

impl S3Backend {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let endpoint = env::var(S3_ENDPOINT_HOST_ENV_VAR)
            .unwrap_or_else(|_| "http://localhost:9000".to_string());

        let config = aws_config::load_from_env().await;
        let s3_config = aws_sdk_s3::config::Builder::from(&config)
            .region(Region::new("RegionOne"))
            .endpoint_url(endpoint.as_str())
            .build();

        let s3_client = aws_sdk_s3::Client::from_conf(s3_config);

        let handler = S3Backend { s3_client };
        Ok(handler)
    }
}

// Data backend for an S3 based storage.
#[async_trait]
impl StorageBackend for S3Backend {
    // Uploads a single object in chunks
    // Objects are uploaded in chunks that come from a channel to allow modification in the data middleware
    // The receiver can directly will be wrapped and will then be directly passed into the s3 client
    async fn put_object(
        &self,
        recv: Receiver<Result<bytes::Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>,
        location: Location,
        content_len: i64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        log::info!("Submitted content-length was: {:#?}", content_len);
        self.check_and_create_bucket(location.bucket.clone())
            .await?;

        let hyper_body = hyper::Body::wrap_stream(recv);
        let bytestream = ByteStream::from(hyper_body);

        match self
            .s3_client
            .put_object()
            .set_bucket(Some(location.bucket))
            .set_key(Some(location.path))
            .set_content_length(Some(content_len))
            .body(bytestream)
            .send()
            .await
        {
            Ok(_) => {}
            Err(err) => {
                log::error!("{}", err);
                return Err(Box::new(err));
            }
        }

        Ok(())
    }

    // Downloads the given object from the s3 storage
    // The body is wrapped into an async reader and reads the data in chunks.
    // The chunks are then transfered into the sender.
    async fn get_object(
        &self,
        location: Location,
        range: Option<Range>,
        sender: Sender<bytes::Bytes>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let mut object = self
            .s3_client
            .get_object()
            .set_bucket(Some(location.bucket))
            .set_key(Some(location.path));

        match range {
            Some(value) => {
                let range_string = format!("Range: bytes={}-{}", value.start, value.end);
                object = object.set_range(Some(range_string));
            }
            None => {}
        }

        let object_request = match object.send().await {
            Ok(value) => value,
            Err(err) => {
                log::error!("{}", err);
                return Err(Box::new(err));
            }
        };

        let body_reader = object_request.body.into_async_read();

        let mut buf_reader = BufReader::with_capacity(65_536, body_reader);

        loop {
            let consumed_len = {
                let buffer_result = buf_reader.fill_buf().await;
                let buf = buffer_result?;
                let buf_len = buf.len();
                let bytes_buf = bytes::Bytes::copy_from_slice(buf);

                match sender.send(bytes_buf).await {
                    Ok(_) => {}
                    Err(err) => {
                        log::error!("{}", err);
                        return Err(Box::new(err));
                    }
                }

                buf_len
            };

            if consumed_len == 0 {
                break;
            }

            buf_reader.consume(consumed_len);
        }

        return Ok(());
    }

    // Initiates a multipart upload in s3 and returns the associated upload id.
    async fn init_multipart_upload(
        &self,
        location: Location,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.check_and_create_bucket(location.bucket.clone())
            .await?;

        let multipart = self
            .s3_client
            .create_multipart_upload()
            .set_bucket(Some(location.bucket))
            .set_key(Some(location.path))
            .send()
            .await?;

        return Ok(multipart.upload_id().unwrap().to_string());
    }

    async fn upload_multi_object(
        &self,
        recv: Receiver<Result<bytes::Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>,
        location: Location,
        upload_id: String,
        content_len: i64,
        part_number: i32,
    ) -> Result<PartETag, Box<dyn std::error::Error + Send + Sync + 'static>> {
        log::info!("Submitted content-length was: {:#?}", content_len);
        let hyper_body = hyper::Body::wrap_stream(recv);
        let bytestream = ByteStream::from(hyper_body);

        let upload = self
            .s3_client
            .upload_part()
            .set_bucket(Some(location.bucket))
            .set_key(Some(location.path))
            .set_part_number(Some(part_number))
            .set_content_length(Some(content_len))
            .set_upload_id(Some(upload_id))
            .body(bytestream)
            .send()
            .await?;

        return Ok(PartETag {
            part_number: part_number as i64,
            etag: upload.e_tag.ok_or(anyhow!(""))?,
        });
    }

    async fn finish_multipart_upload(
        &self,
        location: Location,
        parts: Vec<PartETag>,
        upload_id: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let mut completed_parts = Vec::new();
        for etag in parts {
            let part_number = i32::try_from(etag.part_number)?;

            let completed_part = CompletedPart::builder()
                .e_tag(etag.etag)
                .part_number(part_number)
                .build();

            completed_parts.push(completed_part);
        }

        log::info!("{:?}", completed_parts);

        self.s3_client
            .complete_multipart_upload()
            .bucket(location.bucket)
            .key(location.path)
            .upload_id(upload_id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(completed_parts))
                    .build(),
            )
            .send()
            .await?;

        return Ok(());
    }

    async fn create_bucket(
        &self,
        bucket: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.check_and_create_bucket(bucket).await
    }

    /// Delete a object from the storage system
    /// # Arguments
    /// * `location` - The location of the object
    async fn delete_object(
        &self,
        _location: Location,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        todo!()
    }
}

impl S3Backend {
    pub async fn check_and_create_bucket(
        &self,
        bucket: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        match self
            .s3_client
            .get_bucket_location()
            .bucket(bucket.clone())
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(_) => match self.s3_client.create_bucket().bucket(bucket).send().await {
                Ok(_) => Ok(()),
                Err(err) => {
                    log::error!("{}", err);
                    Err(Box::new(err))
                }
            },
        }
    }
}