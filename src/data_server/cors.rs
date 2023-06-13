use aruna_rust_api::api::internal::v1::CorsConfig;
use aruna_rust_api::api::storage::models::v1::KeyValue;
use http::{
    header::{
        ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    },
    HeaderMap, HeaderValue,
};
use s3s::{dto::CORSRule, s3_error};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct CORSVec {
    pub cors: Vec<CORS>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CORS {
    pub methods: Vec<String>,
    pub origins: Vec<String>,
    pub headers: Vec<String>,
}

impl From<CORSRule> for CORS {
    fn from(cors: CORSRule) -> Self {
        CORS {
            methods: cors.allowed_methods,
            origins: cors.allowed_origins,
            headers: match cors.allowed_headers {
                Some(h) => h,
                None => vec![],
            },
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
                    headers: match x.allowed_headers {
                        Some(h) => h,
                        None => vec![],
                    },
                })
                .collect(),
        }
    }
}

impl From<CORSVec> for Result<Vec<KeyValue>, s3s::S3Error> {
    fn from(cors_vec: CORSVec) -> Self {
        cors_vec
            .cors
            .into_iter()
            .map(|c| {
                Ok(KeyValue {
                    key: "apps.aruna-storage.org/cors".to_string(),
                    value: serde_json::to_string(&c).map_err(|e| {
                        log::debug!("{}", e);
                        s3_error!(InternalError, "Error while parsing CORS headers")
                    })?,
                })
            })
            .collect()
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
                    headers: x.allowed_headers,
                })
                .collect(),
        }
    }
}

impl From<CORSVec> for Result<HeaderMap, s3s::S3Error> {
    fn from(cors_vec: CORSVec) -> Self {
        let mut header_map = HeaderMap::new();
        for c in cors_vec.cors {
            let methods = c.methods.join(",");
            header_map.append(
                ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_str(&methods).map_err(|_| {
                    s3_error!(
                        InternalError,
                        "Provided values for CORS configuration are not valid"
                    )
                })?,
            );
            let origins = c.origins.join(",");
            header_map.append(
                ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_str(&origins).map_err(|_| {
                    s3_error!(
                        InternalError,
                        "Provided values for CORS configuration are not valid"
                    )
                })?,
            );
            let headers = c.headers.join(",");
            header_map.append(
                ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_str(&headers).map_err(|_| {
                    s3_error!(
                        InternalError,
                        "Provided values for CORS configuration are not valid"
                    )
                })?,
            );
        }
        Ok(header_map)
    }
}
impl From<Vec<KeyValue>> for CORSVec {
    fn from(label_vec: Vec<KeyValue>) -> Self {
        let mut cors_vec = CORSVec { cors: vec![] };
        for label in label_vec {
            if label.key.contains("apps.aruna-storage.org/cors") {
                let cors = match serde_json::from_str::<CORS>(&label.value) {
                    Ok(c) => CORS {
                        methods: c.methods,
                        origins: c.origins,
                        headers: c.headers,
                    },
                    // Should not occur, but even if this happens, it should not crash
                    // because CORS headers should not be responsible for panics or errors
                    // when returning objects
                    Err(_) => CORS {
                        methods: vec![],
                        origins: vec![],
                        headers: vec![],
                    },
                };
                cors_vec.cors.push(cors);
            } else {
            }
        }
        cors_vec
    }
}

impl From<CORSVec> for Vec<CORSRule> {
    fn from(cors_vec: CORSVec) -> Self {
        cors_vec
            .cors
            .into_iter()
            .map(|c| CORSRule {
                allowed_methods: c.methods,
                allowed_origins: c.origins,
                allowed_headers: Some(c.headers),
                ..Default::default()
            })
            .collect()
    }
}
