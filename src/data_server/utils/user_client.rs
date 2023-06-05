use s3s::s3_error;
use tonic::metadata::AsciiMetadataKey;
use tonic::metadata::AsciiMetadataValue;
use tonic::transport::Endpoint;
use tonic::transport::{Channel, ClientTlsConfig};

const API_TOKEN_ENTRY_KEY: &str = "Authorization";

#[derive(Clone)]
pub struct UserClient {
    pub interceptor: ClientInterceptor,
    pub endpoint: Endpoint,
}

#[derive(Clone)]
pub struct ClientInterceptor {
    api_token: String,
}

impl UserClient {
    pub async fn new(endpoint: String, api_token: String) -> Result<Self, s3s::S3Error> {
        let interceptor = ClientInterceptor { api_token };
        let tls_config = ClientTlsConfig::new();
        let endpoint = Channel::from_shared(endpoint)
            .map_err(|_| s3_error!(NotSignedUp, "Unable to authenticate user"))?
            .tls_config(tls_config)
            .map_err(|_| s3_error!(NotSignedUp, "Unable to authenticate user"))?;
        Ok(UserClient {
            interceptor,
            endpoint,
        })
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
