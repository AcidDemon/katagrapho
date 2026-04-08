//! High-level verification orchestration for the katagrapho-verify tool.

#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::error::KatagraphoError;
use crate::manifest::{GENESIS_PREV, Manifest};

pub struct VerifyResult {
    pub manifests_checked: usize,
    pub chain_walked: bool,
}

#[allow(dead_code)]
pub fn verify_single(sidecar: &Path, pub_bytes: &[u8; 32]) -> Result<(), KatagraphoError> {
    let m = Manifest::load_from(sidecar)?;
    m.verify(pub_bytes)
}

#[allow(dead_code)]
pub fn verify_recursive(
    dir: &Path,
    pub_bytes: &[u8; 32],
    check_chain: bool,
) -> Result<VerifyResult, KatagraphoError> {
    let mut manifests: Vec<Manifest> = Vec::new();
    walk_collect(dir, &mut manifests)?;
    let total = manifests.len();
    for m in &manifests {
        m.verify(pub_bytes)?;
    }
    if check_chain {
        let mut by_hash: HashMap<&str, &Manifest> = HashMap::new();
        for m in &manifests {
            by_hash.insert(m.this_manifest_hash.as_str(), m);
        }
        for m in &manifests {
            if m.prev_manifest_hash == GENESIS_PREV {
                continue;
            }
            if !by_hash.contains_key(m.prev_manifest_hash.as_str()) {
                return Err(KatagraphoError::Chain(format!(
                    "manifest {} has prev_manifest_hash {} not present in set",
                    m.session_id, m.prev_manifest_hash
                )));
            }
        }
    }
    Ok(VerifyResult {
        manifests_checked: total,
        chain_walked: check_chain,
    })
}

fn walk_collect(dir: &Path, out: &mut Vec<Manifest>) -> Result<(), KatagraphoError> {
    let read = fs::read_dir(dir)
        .map_err(|e| KatagraphoError::Verify(format!("read_dir {}: {e}", dir.display())))?;
    for entry in read {
        let entry = entry.map_err(|e| KatagraphoError::Verify(format!("dir entry: {e}")))?;
        let path = entry.path();
        if path.is_dir() {
            walk_collect(&path, out)?;
        } else if path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.ends_with(".manifest.json"))
            .unwrap_or(false)
        {
            let m = Manifest::load_from(&path)?;
            out.push(m);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::MANIFEST_VERSION;
    use crate::signing::KeyPair;
    use tempfile::tempdir;

    fn make(prev: &str, sid: &str) -> Manifest {
        Manifest {
            v: MANIFEST_VERSION.to_string(),
            session_id: sid.to_string(),
            part: 0,
            user: "u".to_string(),
            host: "h".to_string(),
            boot_id: "b".to_string(),
            audit_session_id: None,
            started: 0.0,
            ended: 1.0,
            katagrapho_version: "0".to_string(),
            katagrapho_commit: "0".to_string(),
            epitropos_version: "0".to_string(),
            epitropos_commit: "0".to_string(),
            recording_file: format!("{sid}.kgv1.age"),
            recording_size: 0,
            recording_sha256: "0".repeat(64),
            chunks: vec![],
            end_reason: "eof".to_string(),
            exit_code: 0,
            prev_manifest_hash: prev.to_string(),
            this_manifest_hash: String::new(),
            key_id: String::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn verify_recursive_walks_chain_clean() {
        let dir = tempdir().unwrap();
        let kp =
            KeyPair::generate_to(&dir.path().join("k.key"), &dir.path().join("k.pub")).unwrap();

        let mut m1 = make(GENESIS_PREV, "s1");
        m1.sign(&kp).unwrap();
        m1.write_to(&dir.path().join("s1.manifest.json")).unwrap();

        let mut m2 = make(&m1.this_manifest_hash, "s2");
        m2.sign(&kp).unwrap();
        m2.write_to(&dir.path().join("s2.manifest.json")).unwrap();

        let result = verify_recursive(dir.path(), &kp.public_bytes(), true).unwrap();
        assert_eq!(result.manifests_checked, 2);
        assert!(result.chain_walked);
    }

    #[test]
    fn verify_recursive_detects_broken_chain() {
        let dir = tempdir().unwrap();
        let kp =
            KeyPair::generate_to(&dir.path().join("k.key"), &dir.path().join("k.pub")).unwrap();

        let mut m1 = make(GENESIS_PREV, "s1");
        m1.sign(&kp).unwrap();
        m1.write_to(&dir.path().join("s1.manifest.json")).unwrap();

        let mut m2 = make(&"f".repeat(64), "s2");
        m2.sign(&kp).unwrap();
        m2.write_to(&dir.path().join("s2.manifest.json")).unwrap();

        assert!(verify_recursive(dir.path(), &kp.public_bytes(), true).is_err());
    }

    #[test]
    fn verify_single_detects_tampered_field() {
        let dir = tempdir().unwrap();
        let kp =
            KeyPair::generate_to(&dir.path().join("k.key"), &dir.path().join("k.pub")).unwrap();
        let mut m = make(GENESIS_PREV, "s1");
        m.sign(&kp).unwrap();
        let path = dir.path().join("s1.manifest.json");
        m.write_to(&path).unwrap();

        // Tamper with the on-disk sidecar: overwrite user field
        let tampered = fs::read_to_string(&path)
            .unwrap()
            .replace("\"user\": \"u\"", "\"user\": \"mallory\"");
        // File has mode 0444, make writable first
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&path, perms).unwrap();
        fs::write(&path, tampered).unwrap();

        assert!(verify_single(&path, &kp.public_bytes()).is_err());
    }
}
