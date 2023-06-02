use s3s::dto::CORSRule;
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
