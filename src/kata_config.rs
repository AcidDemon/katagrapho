//! Optional TOML config file for katagrapho. All fields have defaults.

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::KatagraphoError;

const DEFAULT_MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_MAX_SESSION_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const DEFAULT_KEY_PATH: &str = "/var/lib/katagrapho/signing.key";
const DEFAULT_PUB_PATH: &str = "/var/lib/katagrapho/signing.pub";
const DEFAULT_CHAIN_DIR: &str = "/var/lib/katagrapho";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct KataConfig {
    #[serde(default)]
    pub storage: Storage,
    #[serde(default)]
    pub signing: Signing,
    #[serde(default)]
    pub chain: Chain,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Storage {
    #[serde(default = "Storage::default_max_file")]
    pub max_file_bytes: u64,
    #[serde(default = "Storage::default_max_session")]
    pub max_session_bytes: u64,
}

impl Storage {
    fn default_max_file() -> u64 {
        DEFAULT_MAX_FILE_BYTES
    }
    fn default_max_session() -> u64 {
        DEFAULT_MAX_SESSION_BYTES
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_session_bytes: DEFAULT_MAX_SESSION_BYTES,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Signing {
    #[serde(default = "Signing::default_key")]
    pub key_path: PathBuf,
    #[serde(default = "Signing::default_pub")]
    pub pub_path: PathBuf,
}

impl Signing {
    fn default_key() -> PathBuf {
        PathBuf::from(DEFAULT_KEY_PATH)
    }
    fn default_pub() -> PathBuf {
        PathBuf::from(DEFAULT_PUB_PATH)
    }
}

impl Default for Signing {
    fn default() -> Self {
        Self {
            key_path: PathBuf::from(DEFAULT_KEY_PATH),
            pub_path: PathBuf::from(DEFAULT_PUB_PATH),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Chain {
    #[serde(default = "Chain::default_dir")]
    pub dir: PathBuf,
}

impl Chain {
    fn default_dir() -> PathBuf {
        PathBuf::from(DEFAULT_CHAIN_DIR)
    }
}

impl Default for Chain {
    fn default() -> Self {
        Self {
            dir: PathBuf::from(DEFAULT_CHAIN_DIR),
        }
    }
}

impl Default for KataConfig {
    fn default() -> Self {
        Self {
            storage: Storage::default(),
            signing: Signing::default(),
            chain: Chain::default(),
        }
    }
}

impl KataConfig {
    #[allow(dead_code)]
    pub fn load(path: &Path) -> Result<Self, KatagraphoError> {
        let s = fs::read_to_string(path)
            .map_err(|e| KatagraphoError::Config(format!("read {}: {e}", path.display())))?;
        toml::from_str(&s).map_err(|e| KatagraphoError::Config(format!("parse: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply_when_empty() {
        let cfg: KataConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.storage.max_file_bytes, DEFAULT_MAX_FILE_BYTES);
        assert_eq!(cfg.signing.key_path, PathBuf::from(DEFAULT_KEY_PATH));
    }

    #[test]
    fn parses_storage_overrides() {
        let toml_str = r#"
[storage]
max_file_bytes = 1024
max_session_bytes = 8192
"#;
        let cfg: KataConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.storage.max_file_bytes, 1024);
        assert_eq!(cfg.storage.max_session_bytes, 8192);
    }

    #[test]
    fn rejects_unknown_field() {
        let toml_str = r#"
[storage]
bogus_field = 42
"#;
        let cfg: Result<KataConfig, _> = toml::from_str(toml_str);
        assert!(cfg.is_err());
    }
}
