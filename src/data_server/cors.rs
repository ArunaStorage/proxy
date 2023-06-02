// CORSrule to eigenem Struct implementieren mit FROM

use s3s::dto::CORSRule;

pub struct CORS {
    pub methods: Vec<String>,
    pub origins: Vec<String>,
}

impl From<CORSRule> for CORS {
    fn from(cors: CORSRule) -> Self {
        CORS {
            methods: cors.allowed_methods,
            origins: cors.allowed_origins,
        }
    }
}
