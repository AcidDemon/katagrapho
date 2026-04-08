//! Manifest data model + canonical serialization + sign + verify.
//!
//! Canonicalization is the load-bearing piece: sign and verify MUST
//! produce byte-identical output for logically-equivalent manifests.
//! That guarantee comes from a single code path that builds the
//! canonical JSON with an explicit field order.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::error::KatagraphoError;
use crate::signing::{KeyPair, verify_with_pub};

pub const MANIFEST_VERSION: &str = "katagrapho-manifest-v1";
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    pub seq: u64,
    pub bytes: u64,
    pub messages: u64,
    pub elapsed: f64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub v: String,
    pub session_id: String,
    pub part: u32,
    pub user: String,
    pub host: String,
    pub boot_id: String,
    pub audit_session_id: Option<u32>,
    pub started: f64,
    pub ended: f64,
    pub katagrapho_version: String,
    pub katagrapho_commit: String,
    pub epitropos_version: String,
    pub epitropos_commit: String,
    pub recording_file: String,
    pub recording_size: u64,
    pub recording_sha256: String,
    pub chunks: Vec<Chunk>,
    pub end_reason: String,
    pub exit_code: i32,
    pub prev_manifest_hash: String,
    #[serde(default)]
    pub this_manifest_hash: String,
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub signature: String,
}

impl Manifest {
    /// Serialize the manifest in canonical form, EXCLUDING the three
    /// signature-bearing fields. Used as the input to `this_manifest_hash`.
    fn canonical_bytes_for_hashing(&self) -> Result<Vec<u8>, KatagraphoError> {
        let json = serde_json::to_string(&serde_json::json!({
            "v": self.v,
            "session_id": self.session_id,
            "part": self.part,
            "user": self.user,
            "host": self.host,
            "boot_id": self.boot_id,
            "audit_session_id": self.audit_session_id,
            "started": self.started,
            "ended": self.ended,
            "katagrapho_version": self.katagrapho_version,
            "katagrapho_commit": self.katagrapho_commit,
            "epitropos_version": self.epitropos_version,
            "epitropos_commit": self.epitropos_commit,
            "recording_file": self.recording_file,
            "recording_size": self.recording_size,
            "recording_sha256": self.recording_sha256,
            "chunks": self.chunks,
            "end_reason": self.end_reason,
            "exit_code": self.exit_code,
            "prev_manifest_hash": self.prev_manifest_hash,
        }))
        .map_err(|e| KatagraphoError::Manifest(format!("canonical serialize: {e}")))?;
        Ok(json.into_bytes())
    }

    pub fn compute_hash(&self) -> Result<[u8; 32], KatagraphoError> {
        let bytes = self.canonical_bytes_for_hashing()?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(hasher.finalize().into())
    }

    /// Sign the manifest in place: fills in this_manifest_hash, key_id,
    /// and signature.
    pub fn sign(&mut self, key: &KeyPair) -> Result<[u8; 32], KatagraphoError> {
        let digest = self.compute_hash()?;
        let sig = key.sign(&digest);
        self.this_manifest_hash = hex::encode(digest);
        self.key_id = key.key_id_hex();
        self.signature = base64_encode(&sig);
        Ok(digest)
    }

    pub fn verify(&self, pub_bytes: &[u8; 32]) -> Result<(), KatagraphoError> {
        let recomputed = self.compute_hash()?;
        let stored = hex::decode(&self.this_manifest_hash)
            .map_err(|e| KatagraphoError::Verify(format!("hex decode hash: {e}")))?;
        if stored.len() != 32 {
            return Err(KatagraphoError::Verify(
                "this_manifest_hash wrong length".to_string(),
            ));
        }
        if recomputed[..] != stored[..] {
            return Err(KatagraphoError::Verify(
                "manifest content does not match this_manifest_hash".to_string(),
            ));
        }
        let sig_bytes = base64_decode(&self.signature)
            .map_err(|e| KatagraphoError::Verify(format!("base64 decode sig: {e}")))?;
        if sig_bytes.len() != 64 {
            return Err(KatagraphoError::Verify("signature wrong length".to_string()));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        verify_with_pub(pub_bytes, &recomputed, &sig)
    }

    #[allow(dead_code)]
    pub fn write_to(&self, path: &Path) -> Result<(), KatagraphoError> {
        let tmp = path.with_extension("tmp");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| KatagraphoError::Manifest(format!("serialize: {e}")))?;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o444)
            .open(&tmp)
            .map_err(|e| KatagraphoError::Manifest(format!("open tmp: {e}")))?;
        f.write_all(json.as_bytes())
            .map_err(|e| KatagraphoError::Manifest(format!("write: {e}")))?;
        f.sync_all()
            .map_err(|e| KatagraphoError::Manifest(format!("fsync: {e}")))?;
        drop(f);
        fs::rename(&tmp, path)
            .map_err(|e| KatagraphoError::Manifest(format!("rename: {e}")))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn load_from(path: &Path) -> Result<Self, KatagraphoError> {
        let bytes = fs::read(path)
            .map_err(|e| KatagraphoError::Manifest(format!("read {}: {e}", path.display())))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| KatagraphoError::Manifest(format!("parse {}: {e}", path.display())))
    }
}

// --- inline base64 (avoids dragging in another dep) ---

fn base64_encode(input: &[u8]) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        out.push(ALPH[(b0 >> 2) as usize] as char);
        out.push(ALPH[((b0 & 0x03) << 4 | b1 >> 4) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPH[((b1 & 0x0F) << 2 | b2 >> 6) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPH[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 char: {c}")),
        }
    }
    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err("base64 length not multiple of 4".to_string());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&b| b == b'=').count();
        let v0 = val(chunk[0])?;
        let v1 = val(chunk[1])?;
        let v2 = if pad < 2 { val(chunk[2])? } else { 0 };
        let v3 = if pad < 1 { val(chunk[3])? } else { 0 };
        out.push((v0 << 2) | (v1 >> 4));
        if pad < 2 {
            out.push((v1 << 4) | (v2 >> 2));
        }
        if pad < 1 {
            out.push((v2 << 6) | v3);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample() -> Manifest {
        Manifest {
            v: MANIFEST_VERSION.to_string(),
            session_id: "abc-123".to_string(),
            part: 0,
            user: "alice".to_string(),
            host: "nyx".to_string(),
            boot_id: "00000000-0000-0000-0000-000000000000".to_string(),
            audit_session_id: Some(42),
            started: 1712534400.123,
            ended: 1712534518.551,
            katagrapho_version: "0.3.0".to_string(),
            katagrapho_commit: "abcdef1".to_string(),
            epitropos_version: "0.1.0".to_string(),
            epitropos_commit: "1234567".to_string(),
            recording_file: "abc-123.part0.kgv1.age".to_string(),
            recording_size: 524288,
            recording_sha256: "00".repeat(32),
            chunks: vec![Chunk {
                seq: 0,
                bytes: 1024,
                messages: 8,
                elapsed: 1.5,
                sha256: "aa".repeat(32),
            }],
            end_reason: "eof".to_string(),
            exit_code: 0,
            prev_manifest_hash: GENESIS_PREV.to_string(),
            this_manifest_hash: String::new(),
            key_id: String::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn canonical_bytes_are_stable_across_clones() {
        let m1 = sample();
        let m2 = m1.clone();
        assert_eq!(
            m1.canonical_bytes_for_hashing().unwrap(),
            m2.canonical_bytes_for_hashing().unwrap()
        );
    }

    #[test]
    fn canonical_bytes_ignore_signature_fields() {
        let mut m1 = sample();
        let mut m2 = sample();
        m1.this_manifest_hash = "deadbeef".to_string();
        m1.signature = "garbage".to_string();
        m1.key_id = "irrelevant".to_string();
        m2.this_manifest_hash = "different".to_string();
        m2.signature = "different".to_string();
        m2.key_id = "different".to_string();
        assert_eq!(
            m1.canonical_bytes_for_hashing().unwrap(),
            m2.canonical_bytes_for_hashing().unwrap()
        );
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let dir = tempdir().unwrap();
        let kp = KeyPair::generate_to(&dir.path().join("k.key"), &dir.path().join("k.pub")).unwrap();
        let mut m = sample();
        m.sign(&kp).unwrap();
        m.verify(&kp.public_bytes()).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_field() {
        let dir = tempdir().unwrap();
        let kp = KeyPair::generate_to(&dir.path().join("k.key"), &dir.path().join("k.pub")).unwrap();
        let mut m = sample();
        m.sign(&kp).unwrap();
        m.user = "mallory".to_string();
        assert!(m.verify(&kp.public_bytes()).is_err());
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let dir = tempdir().unwrap();
        let kp = KeyPair::generate_to(&dir.path().join("k.key"), &dir.path().join("k.pub")).unwrap();
        let mut m = sample();
        m.sign(&kp).unwrap();
        let mut chars: Vec<char> = m.signature.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        m.signature = chars.into_iter().collect();
        assert!(m.verify(&kp.public_bytes()).is_err());
    }

    #[test]
    fn write_then_load_round_trip() {
        let dir = tempdir().unwrap();
        let kp = KeyPair::generate_to(&dir.path().join("k.key"), &dir.path().join("k.pub")).unwrap();
        let mut m = sample();
        m.sign(&kp).unwrap();
        let path = dir.path().join("m.json");
        m.write_to(&path).unwrap();
        let loaded = Manifest::load_from(&path).unwrap();
        loaded.verify(&kp.public_bytes()).unwrap();
        assert_eq!(loaded.session_id, m.session_id);
    }

    #[test]
    fn base64_round_trip() {
        let inputs: &[&[u8]] = &[b"", b"a", b"ab", b"abc", b"abcd", b"hello world"];
        for input in inputs {
            let encoded = base64_encode(input);
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(decoded, *input);
        }
    }
}
