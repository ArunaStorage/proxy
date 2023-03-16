use anyhow::Result;
use aruna_file::helpers::footer_parser::Range;
use aruna_rust_api::api::storage::models::v1::Hash;
use aruna_rust_api::api::storage::models::v1::Hashalgorithm;
use aruna_rust_api::api::{
    internal::v1::Location,
    storage::{models::v1::DataClass, services::v1::StageObject},
};
use s3s::s3_error;
use s3s::S3Error;

const FRAMESIZE: i64 = 5242880;
const ENCRYPTION_BLOCKS: i64 = 65536;
const ENCRYPTION_OFFSET: i64 = 28;
const ENCRYPTED_BLOCKS: i64 = ENCRYPTION_BLOCKS + ENCRYPTION_OFFSET;
const ENCRYPTED_FRAMES: i64 = (FRAMESIZE / ENCRYPTION_BLOCKS) * ENCRYPTED_BLOCKS;

pub fn construct_path(bucket: &str, key: &str) -> String {
    format!("s3://{bucket}/{key}")
}

pub fn create_stage_object(key: &str, content_len: i64) -> StageObject {
    let (fname, sub_path) = extract_filename_path(key);
    StageObject {
        filename: fname,
        content_len: content_len,
        source: None,
        dataclass: DataClass::Private as i32,
        labels: Vec::new(),
        hooks: Vec::new(),
        sub_path: sub_path,
    }
}

pub fn extract_filename_path(path: &str) -> (String, String) {
    let mut splits: Vec<&str> = path.split('/').collect();
    (
        String::from(splits.pop().unwrap_or_else(|| "")),
        splits.join("/"),
    )
}

pub fn create_location_from_hash(
    sha256_hash: &str,
    object_id: &str,
    collection_id: &str,
    encrypting: bool,
    compressing: bool,
    encryption_key: String,
) -> (Location, bool) {
    if sha256_hash.is_empty() {
        (
            // For now we do not compress temp values
            Location {
                bucket: "temp".to_string(),
                is_compressed: false,
                is_encrypted: encrypting,
                encryption_key,
                path: format!("{}/{}", collection_id, object_id),
                ..Default::default()
            },
            true,
        )
    } else {
        (
            Location {
                bucket: sha256_hash[0..2].to_string(),
                path: sha256_hash[2..].to_string(),
                is_compressed: compressing,
                is_encrypted: encrypting,
                encryption_key,
                ..Default::default()
            },
            false,
        )
    }
}

pub fn validate_and_check_hashes(
    s3_md5_hash: Option<String>,
    s3_sha256_hash: Option<String>,
    backend_hashes: Vec<Hash>,
) -> Result<(String, String), S3Error> {
    let mut hash_md5 = match s3_md5_hash {
        Some(h) => h,
        None => String::new(),
    };
    let mut hash_sha256 = match s3_sha256_hash {
        Some(h) => h,
        None => String::new(),
    };

    for hash in backend_hashes {
        match Hashalgorithm::from_i32(hash.alg) {
            Some(Hashalgorithm::Md5) => {
                if !hash_md5.is_empty() {
                    if hash.hash != hash_md5 {
                        return Err(s3_error!(
                            InvalidDigest,
                            "Invalid or inconsistent MD5 digest"
                        ));
                    }
                }
                hash_md5 = hash.hash;
            }
            Some(Hashalgorithm::Sha256) => {
                if !hash_sha256.is_empty() {
                    if hash.hash != hash_sha256 {
                        return Err(s3_error!(
                            InvalidDigest,
                            "Invalid or inconsistent SHA256 digest"
                        ));
                    }
                }
                hash_sha256 = hash.hash;
            }
            _ => {}
        }
    }

    if !hash_md5.is_empty() {
        if hash_md5.len() != 32 {
            return Err(s3_error!(
                InvalidDigest,
                "Invalid or inconsistent MD5 digest"
            ));
        }
    }

    if !hash_sha256.is_empty() {
        if hash_sha256.len() != 64 {
            return Err(s3_error!(
                InvalidDigest,
                "Invalid or inconsistent SHA256 digest"
            ));
        }
    }

    Ok((hash_md5, hash_sha256))
}

pub fn create_ranges(expected_size: i64, from: Location) -> Vec<Range> {
    if from.is_encrypted {
        (0..expected_size % ENCRYPTED_FRAMES as i64)
            .map(|e| {
                if (e + 1) * ENCRYPTED_BLOCKS < expected_size {
                    Range {
                        from: (e * ENCRYPTED_BLOCKS) as u64,
                        to: ((e + 1) * ENCRYPTED_BLOCKS) as u64,
                    }
                } else {
                    Range {
                        from: (e * ENCRYPTED_BLOCKS) as u64,
                        to: expected_size as u64,
                    }
                }
            })
            .collect::<Vec<Range>>()
    } else {
        (0..expected_size % FRAMESIZE as i64)
            .map(|e| {
                if (e + 1) * ENCRYPTION_BLOCKS < expected_size {
                    Range {
                        from: (e * ENCRYPTION_BLOCKS) as u64,
                        to: ((e + 1) * ENCRYPTION_BLOCKS) as u64,
                    }
                } else {
                    Range {
                        from: (e * ENCRYPTION_BLOCKS) as u64,
                        to: expected_size as u64,
                    }
                }
            })
            .collect::<Vec<Range>>()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn extract_filename_path_test() {
        use super::*;
        let test = "";

        assert_eq!(
            extract_filename_path(test),
            ("".to_string(), "".to_string())
        );

        let test = "a/a";
        assert_eq!(
            extract_filename_path(test),
            ("a".to_string(), "a".to_string())
        );

        let test = "/a";
        assert_eq!(
            extract_filename_path(test),
            ("a".to_string(), "".to_string())
        );
    }
}