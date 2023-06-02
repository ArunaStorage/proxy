use aruna_rust_api::aruna::aruna::api::storage::services::v1::collection_service_client;
use tonic::codegen::InterceptedService;
use tonic::metadata::AsciiMetadataKey;
use tonic::metadata::AsciiMetadataValue;
use tonic::transport::{Channel, ClientTlsConfig};

const API_TOKEN_ENTRY_KEY: &str = "Authorization";

#[derive(Clone)]
pub struct UserClient {
    pub collection_service: collection_service_client::CollectionServiceClient<
        InterceptedService<Channel, ClientInterceptor>,
    >,
}

#[derive(Clone)]
pub struct ClientInterceptor {
    api_token: String,
}

impl UserClient {
    pub async fn new(endpoint: String, api_token: String) -> Self {
        let interceptor = ClientInterceptor { api_token };
        let tls_config = ClientTlsConfig::new();
        let endpoint = Channel::from_shared(endpoint)
            .unwrap()
            .tls_config(tls_config)
            .unwrap();
        let channel = endpoint.connect().await.unwrap();
        let client = UserClient {
            collection_service:
                collection_service_client::CollectionServiceClient::with_interceptor(
                    channel.clone(),
                    interceptor.clone(),
                ),
        };

        return client;
    }
}

impl tonic::service::Interceptor for ClientInterceptor {
    fn call(&mut self, request: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        let mut mut_req: tonic::Request<()> = request;
        let metadata = mut_req.metadata_mut();
        metadata.append(
            AsciiMetadataKey::from_bytes(API_TOKEN_ENTRY_KEY.as_bytes()).unwrap(),
            AsciiMetadataValue::try_from(format!("Bearer {}", self.api_token.as_str())).unwrap(),
        );

        return Ok(mut_req);
    }
}
