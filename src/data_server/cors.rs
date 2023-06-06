use aruna_rust_api::api::internal::v1::CorsConfig;
use http::{
    header::{
        ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    },
    HeaderMap, HeaderValue,
};
use s3s::{dto::CORSRule, s3_error};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CORSVec {
    pub cors: Vec<CORS>,
}

#[derive(Serialize, Deserialize)]
pub struct CORS {
    pub methods: Vec<String>,
    pub origins: Vec<String>,
    pub headers: Option<Vec<String>>,
}

impl From<CORSRule> for CORS {
    fn from(cors: CORSRule) -> Self {
        CORS {
            methods: cors.allowed_methods,
            origins: cors.allowed_origins,
            headers: cors.allowed_headers,
        }
    }
}

impl From<Vec<CORSRule>> for CORSVec {
    fn from(cors_vec: Vec<CORSRule>) -> Self {
        CORSVec {
            cors: cors_vec
                .into_iter()
                .map(|x| CORS {
                    methods: x.allowed_methods,
                    origins: x.allowed_origins,
                    headers: x.allowed_headers,
                })
                .collect(),
        }
    }
}

impl From<Vec<CorsConfig>> for CORSVec {
    fn from(cors_vec: Vec<CorsConfig>) -> Self {
        CORSVec {
            cors: cors_vec
                .into_iter()
                .map(|x| CORS {
                    methods: x.allowed_methods,
                    origins: x.allowed_origins,
                    headers: if x.allowed_headers.is_empty() {
                        None
                    } else {
                        Some(x.allowed_headers)
                    },
                })
                .collect(),
        }
    }
}

impl From<CORSVec> for Result<HeaderMap, s3s::S3Error> {
    fn from(cors_vec: CORSVec) -> Self {
        let mut header_map = HeaderMap::new();
        for c in cors_vec.cors {
            for s in c.methods {
                header_map.insert(
                    ACCESS_CONTROL_ALLOW_METHODS,
                    HeaderValue::from_str(&s).map_err(|_| {
                        s3_error!(
                            InternalError,
                            "Provided values for CORS configuration are not valid"
                        )
                    })?,
                );
            }
            for s in c.origins {
                header_map.insert(
                    ACCESS_CONTROL_ALLOW_ORIGIN,
                    HeaderValue::from_str(&s).map_err(|_| {
                        s3_error!(
                            InternalError,
                            "Provided values for CORS configuration are not valid"
                        )
                    })?,
                );
            }
            match c.headers {
                Some(h) => {
                    for s in h {
                        header_map.insert(
                            ACCESS_CONTROL_ALLOW_HEADERS,
                            HeaderValue::from_str(&s).map_err(|_| {
                                s3_error!(
                                    InternalError,
                                    "Provided values for CORS configuration are not valid"
                                )
                            })?,
                        );
                    }
                }
                None => (),
            };
        }
        Ok(header_map)
    }
}
