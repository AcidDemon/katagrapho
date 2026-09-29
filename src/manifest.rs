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
    ///
    /// The field order below is explicit and alphabetical, and the object is
    /// assembled here rather than handed to a `serde_json::Map`. It used to be
    /// a `json!` literal, which produced these same bytes only because a Map
    /// is a `BTreeMap` under serde_json's default features and therefore sorts
    /// its keys. Enabling serde_json's `preserve_order` anywhere in the
    /// dependency graph would switch that to an `IndexMap`, emit the fields in
    /// literal order instead, and change every byte: every signature ever
    /// written would stop verifying, and theatron, which reproduces this
    /// digest independently, would disagree with the recorder. A canonical
    /// form cannot depend on a cargo feature.
    fn canonical_bytes_for_hashing(&self) -> Result<Vec<u8>, KatagraphoError> {
        fn enc<T: Serialize>(v: &T) -> Result<String, KatagraphoError> {
            serde_json::to_string(v)
                .map_err(|e| KatagraphoError::Manifest(format!("canonical serialize: {e}")))
        }

        // Chunks need the same treatment for the same reason, one level down.
        // The json! literal turned each Chunk into a Value, so its keys were
        // sorted too; serializing the struct directly would emit them in
        // declaration order and change the digest. Alphabetical, explicitly.
        fn enc_chunks(chunks: &[Chunk]) -> Result<String, KatagraphoError> {
            let mut out = String::from("[");
            for (i, c) in chunks.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&format!(
                    "{{\"bytes\":{},\"elapsed\":{},\"messages\":{},\"seq\":{},\"sha256\":{}}}",
                    enc(&c.bytes)?,
                    enc(&c.elapsed)?,
                    enc(&c.messages)?,
                    enc(&c.seq)?,
                    enc(&c.sha256)?
                ));
            }
            out.push(']');
            Ok(out)
        }

        let fields: [(&str, String); 20] = [
            ("audit_session_id", enc(&self.audit_session_id)?),
            ("boot_id", enc(&self.boot_id)?),
            ("chunks", enc_chunks(&self.chunks)?),
            ("end_reason", enc(&self.end_reason)?),
            ("ended", enc(&self.ended)?),
            ("epitropos_commit", enc(&self.epitropos_commit)?),
            ("epitropos_version", enc(&self.epitropos_version)?),
            ("exit_code", enc(&self.exit_code)?),
            ("host", enc(&self.host)?),
            ("katagrapho_commit", enc(&self.katagrapho_commit)?),
            ("katagrapho_version", enc(&self.katagrapho_version)?),
            ("part", enc(&self.part)?),
            ("prev_manifest_hash", enc(&self.prev_manifest_hash)?),
            ("recording_file", enc(&self.recording_file)?),
            ("recording_sha256", enc(&self.recording_sha256)?),
            ("recording_size", enc(&self.recording_size)?),
            ("session_id", enc(&self.session_id)?),
            ("started", enc(&self.started)?),
            ("user", enc(&self.user)?),
            ("v", enc(&self.v)?),
        ];

        let mut out = String::from("{");
        for (i, (key, value)) in fields.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('"');
            out.push_str(key);
            out.push_str("\":");
            out.push_str(value);
        }
        out.push('}');
        Ok(out.into_bytes())
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
            return Err(KatagraphoError::Verify(
                "signature wrong length".to_string(),
            ));
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
        fs::rename(&tmp, path).map_err(|e| KatagraphoError::Manifest(format!("rename: {e}")))?;
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

// Signatures are stored as standard (RFC 4648) base64 with padding. The 57
// hand-rolled lines this replaces produced the same bytes; the base64 crate is
// already in the lock file via age, so there was nothing to avoid.
pub fn base64_encode(input: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, input)
}

pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, input)
        .map_err(|e| format!("invalid base64: {e}"))
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
        let kp =
            KeyPair::generate_to(&dir.path().join("k.key"), &dir.path().join("k.pub")).unwrap();
        let mut m = sample();
        m.sign(&kp).unwrap();
        m.verify(&kp.public_bytes()).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_field() {
        let dir = tempdir().unwrap();
        let kp =
            KeyPair::generate_to(&dir.path().join("k.key"), &dir.path().join("k.pub")).unwrap();
        let mut m = sample();
        m.sign(&kp).unwrap();
        m.user = "mallory".to_string();
        assert!(m.verify(&kp.public_bytes()).is_err());
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let dir = tempdir().unwrap();
        let kp =
            KeyPair::generate_to(&dir.path().join("k.key"), &dir.path().join("k.pub")).unwrap();
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
        let kp =
            KeyPair::generate_to(&dir.path().join("k.key"), &dir.path().join("k.pub")).unwrap();
        let mut m = sample();
        m.sign(&kp).unwrap();
        let path = dir.path().join("m.json");
        m.write_to(&path).unwrap();
        let loaded = Manifest::load_from(&path).unwrap();
        loaded.verify(&kp.public_bytes()).unwrap();
        assert_eq!(loaded.session_id, m.session_id);
    }

    #[test]
    fn canonical_bytes_match_the_sorted_map_encoding() {
        // The bytes every existing signature was computed over. This asserts
        // the hand-assembled object is byte-identical to what serde_json's
        // default (BTreeMap-backed) Map produced, so replacing the json!
        // literal cannot have invalidated anything on disk.
        let m = sample();
        let legacy = serde_json::to_string(&serde_json::json!({
            "v": m.v,
            "session_id": m.session_id,
            "part": m.part,
            "user": m.user,
            "host": m.host,
            "boot_id": m.boot_id,
            "audit_session_id": m.audit_session_id,
            "started": m.started,
            "ended": m.ended,
            "katagrapho_version": m.katagrapho_version,
            "katagrapho_commit": m.katagrapho_commit,
            "epitropos_version": m.epitropos_version,
            "epitropos_commit": m.epitropos_commit,
            "recording_file": m.recording_file,
            "recording_size": m.recording_size,
            "recording_sha256": m.recording_sha256,
            "chunks": m.chunks,
            "end_reason": m.end_reason,
            "exit_code": m.exit_code,
            "prev_manifest_hash": m.prev_manifest_hash,
        }))
        .unwrap();
        let actual = String::from_utf8(m.canonical_bytes_for_hashing().unwrap()).unwrap();
        assert_eq!(actual, legacy);
        // And the order is the alphabetical one, not the listing order.
        assert!(actual.starts_with("{\"audit_session_id\":"), "{actual}");
        assert!(
            actual.ends_with(",\"v\":\"katagrapho-manifest-v1\"}"),
            "{actual}"
        );
    }

    #[test]
    fn canonical_bytes_cover_every_unsigned_field() {
        // A field added to the struct but not to the canonical encoding would
        // be unsigned: an attacker could change it freely and the signature
        // would still verify. Count the struct's fields against the encoding's.
        let m = sample();
        let all = match serde_json::to_value(&m).unwrap() {
            serde_json::Value::Object(o) => o.len(),
            other => panic!("manifest should serialize to an object, got {other:?}"),
        };
        let canonical = match serde_json::from_slice::<serde_json::Value>(
            &m.canonical_bytes_for_hashing().unwrap(),
        )
        .unwrap()
        {
            serde_json::Value::Object(o) => o.len(),
            other => panic!("canonical form should be an object, got {other:?}"),
        };
        // this_manifest_hash, key_id and signature are excluded by design.
        assert_eq!(
            canonical,
            all - 3,
            "every field except the three signature-bearing ones must be signed"
        );
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        // Existing manifests were signed with a hand-rolled encoder. These are
        // the RFC 4648 vectors it produced, so a swap that changes a byte here
        // would invalidate every signature already on disk.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(&[0xff, 0xfe, 0xfd]), "//79");
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar".to_vec());
        assert!(base64_decode("not base64!").is_err());
    }

    #[test]
    fn base64_round_trip() {
        let inputs: &[&[u8]] = &[b"", b"a", b"ab", b"abc", b"abcd", b"hello world"];
        for input in inputs {
            let encoded = base64_encode(input);
            assert!(
                !encoded.contains('-') && !encoded.contains('_'),
                "must stay standard-alphabet base64, not URL-safe: {encoded}"
            );
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(decoded, *input);
        }
    }
}
