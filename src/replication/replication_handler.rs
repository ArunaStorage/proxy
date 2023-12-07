use crate::{
    caching::cache::Cache,
    data_backends::storage_backend::StorageBackend,
    s3_frontend::utils::buffered_s3_sink::BufferedS3Sink,
    structs::{Object, ObjectLocation},
    trace_err,
};
use ahash::{HashSet, RandomState};
use anyhow::{anyhow, Result};
use aruna_file::{
    streamreadwrite::ArunaStreamReadWriter,
    transformer::ReadWriter,
    transformers::{
        encrypt::ChaCha20Enc, footer::FooterGenerator, gzip_comp::GzipEnc,
        hashing_transformer::HashingTransformer, size_probe::SizeProbe, zstd_comp::ZstdEnc,
    },
};
use aruna_rust_api::api::{
    dataproxy::services::v2::{
        error_message, pull_replication_request::Message,
        pull_replication_response::Message as ResponseMessage, Chunk, ChunkAckMessage,
        InfoAckMessage, InitMessage, PullReplicationRequest, RetryChunkMessage,
    },
    storage::services::v2::UpdateReplicationStatusRequest,
};
use aruna_rust_api::api::{
    dataproxy::services::v2::{ObjectInfo, ReplicationStatus},
    storage::models::v2::{Hash, Hashalgorithm},
};
use async_channel::{Receiver, Sender};
use dashmap::{DashMap, DashSet};
use diesel_ulid::DieselUlid;
use futures_util::TryStreamExt;
use md5::{Digest, Md5};
use sha2::Sha256;
use std::{collections::HashMap, str::FromStr, sync::Arc};
use tokio::pin;
use tracing::{error, trace};

pub struct ReplicationMessage {
    pub direction: Direction,
    pub endpoint_id: DieselUlid,
}

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub enum Direction {
    Push(DieselUlid),
    Pull(DieselUlid),
}

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub enum RcvSync {
    RcvInfo(DieselUlid, i64),  // object_id and how many chunks
    RcvChunk(DieselUlid, i64), // object_id and which chunk
    RcvFinish,
}
pub struct DataChunk {
    pub object_id: String,
    pub chunk_idx: i64,
    pub data: Vec<u8>,
    pub checksum: String,
}

pub struct ReplicationHandler {
    pub receiver: Receiver<ReplicationMessage>,
    pub backend: Arc<Box<dyn StorageBackend>>,
    pub self_id: String,
}

impl ReplicationHandler {
    #[tracing::instrument(level = "trace")]
    pub fn new(
        receiver: Receiver<ReplicationMessage>,
        backend: Arc<Box<dyn StorageBackend>>,
        self_id: String,
    ) -> Self {
        Self {
            receiver,
            backend,
            self_id,
        }
    }

    #[tracing::instrument(level = "trace", skip(self, cache))]
    pub async fn run(self, cache: Arc<Cache>) -> Result<()> {
        // Has EndpointID: [Pull(object_id), Pull(object_id) ,...]
        let queue: Arc<DashMap<DieselUlid, Vec<Direction>, RandomState>> =
            Arc::new(DashMap::default());

        // Push messages into DashMap for deduplication
        let queue_clone = queue.clone();
        let receiver = self.receiver.clone();
        let recieve = tokio::spawn(async move {
            while let Ok(ReplicationMessage {
                direction,
                endpoint_id,
            }) = receiver.recv().await
            {
                queue_clone.alter(&endpoint_id, |_, mut objects| {
                    objects.push(direction.clone());
                    objects
                });
            }
        });

        // Proccess DashMap entries in separate task
        let backend = self.backend.clone();
        let self_id = self.self_id.clone();
        let process: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            loop {
                // Process batches every 30 seconds
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let batch = queue.clone();

                let result = ReplicationHandler::process(
                    self_id.clone(),
                    batch,
                    cache.clone(),
                    backend.clone(),
                )
                .await?;
                for id in result {
                    let entry = queue.remove(&id);
                    if entry.is_none() {
                        return Err(anyhow!("Tried to remove non existing object from queue"));
                    };
                }
            }
        });
        // Run both tasks simultaneously
        let _ = trace_err!(tokio::try_join!(recieve, process))?;
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(cache, backend))]
    // TODO
    // - Pull/Push logic
    // - write objects into storage backend
    // - write objects into cache/db
    async fn process(
        self_id: String,
        batch: Arc<DashMap<DieselUlid, Vec<Direction>, ahash::RandomState>>,
        cache: Arc<Cache>,
        backend: Arc<Box<dyn StorageBackend>>,
    ) -> Result<Vec<DieselUlid>> {
        let mut result = Vec::new();

        // Iterates over each endpoint
        for endpoint in batch.iter() {
            // Collects all objects for each direction
            let pull: Vec<DieselUlid> = endpoint
                .iter()
                .filter_map(|object| match object {
                    Direction::Pull(id) => Some(*id),
                    Direction::Push(_) => None,
                })
                .collect();
            let _push: Vec<DieselUlid> = endpoint
                .iter()
                .filter_map(|object| match object {
                    Direction::Push(id) => Some(*id),
                    Direction::Pull(_) => None,
                })
                .collect();
            let init_request = PullReplicationRequest {
                message: Some(Message::InitMessage(InitMessage {
                    dataproxy_id: self_id.clone(),
                    object_ids: pull.iter().map(|o| o.to_string()).collect(),
                })),
            };

            if let Some(query_handler) = cache.aruna_client.read().await.as_ref() {
                let (request_sender, mut response_stream) = query_handler
                    .pull_replication(init_request, self_id.clone())
                    .await?;
                let (sync_sender, sync_receiver) = async_channel::bounded(100);
                let (finish_sender, finish_receiver) = async_channel::bounded(1);
                let object_handler_map: Arc<
                    DashMap<String, (Sender<DataChunk>, Receiver<DataChunk>), ahash::RandomState>,
                > = Arc::new(DashMap::default());

                // Response handler
                let data_map = object_handler_map.clone();
                let sync_sender_clone = sync_sender.clone();
                tokio::spawn(async move {
                    while let Some(response) = response_stream.message().await? {
                        match response.message {
                            Some(ResponseMessage::ObjectInfo(ObjectInfo {
                                object_id,
                                chunks,
                                ..
                            })) => {
                                let id = DieselUlid::from_str(&object_id)?;
                                sync_sender_clone.send(RcvSync::RcvInfo(id, chunks)).await?;
                                let object_channel = async_channel::bounded(100);
                                data_map.insert(object_id.clone(), object_channel.clone());
                                request_sender
                                    .send(PullReplicationRequest {
                                        message: Some(Message::InfoAckMessage(InfoAckMessage {
                                            object_id,
                                        })),
                                    })
                                    .await?;
                            }
                            Some(ResponseMessage::Chunk(Chunk {
                                object_id,
                                chunk_idx,
                                data,
                                checksum,
                            })) => {
                                if let Some(entry) = data_map.get(&object_id) {
                                    let chunk = DataChunk {
                                        object_id: object_id.clone(),
                                        chunk_idx,
                                        data,
                                        checksum,
                                    };
                                    entry.0.send(chunk).await?;
                                    let id = DieselUlid::from_str(&object_id)?;
                                    sync_sender_clone
                                        .send(RcvSync::RcvChunk(id, chunk_idx))
                                        .await?;
                                    request_sender
                                        .send(PullReplicationRequest {
                                            message: Some(Message::ChunkAckMessage(
                                                ChunkAckMessage {
                                                    object_id,
                                                    chunk_idx,
                                                },
                                            )),
                                        })
                                        .await?;
                                } else {
                                    request_sender
                                        .send(
                                            PullReplicationRequest {
                                                message: Some(
                                                    Message::ErrorMessage(
                                                        aruna_rust_api::api::dataproxy::services::v2::ErrorMessage {
                                                            error: Some(
                                                                error_message::Error::RetryChunk(
                                                                    {
                                                                        RetryChunkMessage {
                                                                            object_id,
                                                                            chunk_idx,
                                                                        }
                                                                    }
                                                                )
                                                            )
                                                        }
                                                    )
                                                )
                                            }
                                        )
                                        .await?;
                                }
                            }
                            Some(ResponseMessage::FinishMessage(..)) => return Ok(()),
                            None => {
                                return Err(anyhow!(
                                    "No message provided in PullReplicationResponse"
                                ))
                            }
                        }
                    }
                    Ok::<(), anyhow::Error>(())
                });

                // Sync handler
                tokio::spawn(async move {
                    let mut sync = HashSet::default();
                    while let Ok(msg) = sync_receiver.recv().await {
                        match msg {
                            info @ RcvSync::RcvInfo(..) => {
                                sync.insert(info);
                            }
                            chunk @ RcvSync::RcvChunk(..) => {
                                sync.insert(chunk);
                            }
                            RcvSync::RcvFinish => {
                                finish_sender.send(sync.clone()).await?;
                            }
                        }
                    }
                    Ok::<(), anyhow::Error>(())
                });

                // Process each object
                let cache = cache.clone();
                let backend = backend.clone();
                tokio::spawn(async move {
                    for entry in object_handler_map.iter() {
                        let (id, channel) = entry.pair();
                        let object_id = DieselUlid::from_str(id)?;
                        let entry = cache
                            .resources
                            .get(&object_id)
                            .ok_or_else(|| anyhow!("Object not found"))?;
                        let (object, location) = entry.value();
                        let location = if let Some(location) = location {
                            location.clone()
                        } else {
                            backend
                                .initialize_location(&object, None, None, false)
                                .await?
                        };
                        ReplicationHandler::load_into_backend(
                            channel.1.clone(),
                            location,
                            backend.clone(),
                        );
                        // TODO:
                        // - Sync with cache and db
                    }
                    sync_sender.send(RcvSync::RcvFinish).await?;
                    while let Ok(finished) = finish_receiver.recv().await {
                        todo!()
                    }
                    Ok::<(), anyhow::Error>(())
                });
                // TODO
                // - if successfull write into results
                result.push(endpoint.key().clone());
            };
        }

        Ok(result)
    }
    async fn load_into_backend(
        data_receiver: Receiver<DataChunk>,
        mut location: ObjectLocation,
        backend: Arc<Box<dyn StorageBackend>>,
    ) -> Result<()> {
        // TODO:
        // - Remove zstd encoding
        // - retrieve chunk hashes
        // - send error if chunk_hash differs
        let (data_sender, data_stream) = async_channel::bounded(100);
        tokio::spawn(async move {
            while let Ok(data) = data_receiver.recv().await {
                data_sender
                    .send(Ok(bytes::Bytes::from_iter(data.data.into_iter())))
                    .await?;
            }
            Ok::<(), anyhow::Error>(())
        });

        // Initialize hashing transformers
        let (initial_size_trans, initial_size_recv) = SizeProbe::new();
        let (final_sha_trans, final_sha_recv) = HashingTransformer::new(Sha256::new());
        let (final_size_trans, final_size_recv) = SizeProbe::new();

        let location_clone = location.clone();
        tokio::spawn(async move {
            pin!(data_stream);
            let mut awr = ArunaStreamReadWriter::new_with_sink(
                data_stream,
                BufferedS3Sink::new(
                    backend.clone(),
                    location_clone.clone(),
                    None,
                    None,
                    false,
                    None,
                    false,
                )
                .0,
            );

            awr = awr.add_transformer(initial_size_trans);

            if location_clone.compressed {
                trace!("adding zstd decompressor");
                awr = awr.add_transformer(ZstdEnc::new(true));
                if location_clone.raw_content_len > 5242880 + 80 * 28 {
                    trace!("adding footer generator");
                    awr = awr.add_transformer(FooterGenerator::new(None))
                }
            }

            if let Some(enc_key) = &location_clone.encryption_key {
                awr = awr.add_transformer(trace_err!(ChaCha20Enc::new(
                    true,
                    enc_key.to_string().into_bytes()
                ))?);
            }

            awr = awr.add_transformer(final_sha_trans);
            awr = awr.add_transformer(final_size_trans);

            trace_err!(awr.process().await)?;
            Ok::<(), anyhow::Error>(())
        });

        // Fetch calculated hashes
        trace!("fetching hashes");
        let sha_final: String = trace_err!(final_sha_recv.try_recv())?;
        let initial_size: u64 = trace_err!(initial_size_recv.try_recv())?;
        let final_size: u64 = trace_err!(final_size_recv.try_recv())?;
        //
        // Put infos into location
        //location.id = object.id;
        location.raw_content_len = initial_size as i64;
        location.disk_content_len = final_size as i64;
        location.disk_hash = Some(sha_final.clone());

        Ok(())
    }
}
