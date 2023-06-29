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
        let endpoint = if endpoint.starts_with("http://") {
            tonic::transport::Endpoint::try_from(endpoint)
                .map_err(|_| s3_error!(InternalError, "Unable to connect to endpoint"))?
        } else if endpoint.starts_with("https://") {
            Channel::from_shared(endpoint)
                .map_err(|e| {
                    log::error!("{}", e);
                    s3_error!(InternalError, "Unable to connect to endpoint")
                })?
                .tls_config(tls_config)
                .map_err(|_| s3_error!(InternalError, "Unable to connect to endpoint"))?
        } else {
            return Err(s3_error!(InternalError, "Unable to connect to endpoint"));
        };
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
            AsciiMetadataKey::from_bytes(API_TOKEN_ENTRY_KEY.as_bytes()).map_err(|_| {
                tonic::Status::invalid_argument("Error while parsing authorization header")
            })?,
            AsciiMetadataValue::try_from(format!("Bearer {}", self.api_token.as_str()))
                .map_err(|_| tonic::Status::invalid_argument("Invalid Bearer Token"))?,
        );

        return Ok(mut_req);
    }
}
