//! Ed25519 key loading and signing for katagrapho manifests.
//!
//! The private key lives at /var/lib/katagrapho/signing.key as a
//! 32-byte raw seed (no PEM, no envelope). The public key is at
//! signing.pub as 32 raw bytes. Both are loaded once at startup
//! after privilege drop.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::error::KatagraphoError;

pub struct KeyPair {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl KeyPair {
    /// Load the private+public key from the given paths.
    /// Verifies that the public key is consistent with the private key.
    pub fn load(key_path: &Path, pub_path: &Path) -> Result<Self, KatagraphoError> {
        let key_bytes = fs::read(key_path)
            .map_err(|e| KatagraphoError::Signing(format!("read {}: {e}", key_path.display())))?;
        if key_bytes.len() != 32 {
            return Err(KatagraphoError::Signing(format!(
                "{} must be exactly 32 bytes, got {}",
                key_path.display(),
                key_bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&key_bytes);
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();

        if pub_path.exists() {
            let on_disk = fs::read(pub_path).map_err(|e| {
                KatagraphoError::Signing(format!("read {}: {e}", pub_path.display()))
            })?;
            if on_disk.len() != 32 || on_disk != verifying.as_bytes() {
                return Err(KatagraphoError::Signing(
                    "signing.pub does not match signing.key".to_string(),
                ));
            }
        }

        Ok(Self { signing, verifying })
    }

    /// Generate a fresh key pair and write both files atomically.
    #[allow(dead_code)]
    pub fn generate_to(key_path: &Path, pub_path: &Path) -> Result<Self, KatagraphoError> {
        use rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();

        let key_tmp = key_path.with_extension("tmp");
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o400)
            .open(&key_tmp)
            .map_err(|e| KatagraphoError::Signing(format!("open key tmp: {e}")))?;
        f.write_all(signing.as_bytes())
            .map_err(|e| KatagraphoError::Signing(format!("write key: {e}")))?;
        f.sync_all()
            .map_err(|e| KatagraphoError::Signing(format!("fsync key: {e}")))?;
        drop(f);
        fs::rename(&key_tmp, key_path)
            .map_err(|e| KatagraphoError::Signing(format!("rename key: {e}")))?;

        let pub_tmp = pub_path.with_extension("tmp");
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o444)
            .open(&pub_tmp)
            .map_err(|e| KatagraphoError::Signing(format!("open pub tmp: {e}")))?;
        f.write_all(verifying.as_bytes())
            .map_err(|e| KatagraphoError::Signing(format!("write pub: {e}")))?;
        f.sync_all()
            .map_err(|e| KatagraphoError::Signing(format!("fsync pub: {e}")))?;
        drop(f);
        fs::rename(&pub_tmp, pub_path)
            .map_err(|e| KatagraphoError::Signing(format!("rename pub: {e}")))?;

        Ok(Self { signing, verifying })
    }

    /// Sign a 32-byte digest. Returns the 64-byte signature.
    pub fn sign(&self, digest: &[u8; 32]) -> [u8; 64] {
        self.signing.sign(digest).to_bytes()
    }

    /// SHA-256 of the public key, as a hex string. Used as `key_id` in manifests.
    pub fn key_id_hex(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.verifying.as_bytes());
        hex::encode(hasher.finalize())
    }

    #[allow(dead_code)]
    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }
}

/// Verify a signature against a digest using a raw 32-byte pubkey.
pub fn verify_with_pub(
    pub_bytes: &[u8; 32],
    digest: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), KatagraphoError> {
    let vk = VerifyingKey::from_bytes(pub_bytes)
        .map_err(|e| KatagraphoError::Verify(format!("invalid pubkey: {e}")))?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    vk.verify(digest, &sig)
        .map_err(|e| KatagraphoError::Verify(format!("signature mismatch: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generate_load_round_trip() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("signing.key");
        let pub_path = dir.path().join("signing.pub");

        let kp = KeyPair::generate_to(&key_path, &pub_path).unwrap();
        let kp2 = KeyPair::load(&key_path, &pub_path).unwrap();
        assert_eq!(kp.public_bytes(), kp2.public_bytes());
    }

    #[test]
    fn load_rejects_short_key() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("short.key");
        let pub_path = dir.path().join("short.pub");
        fs::write(&key_path, b"too short").unwrap();
        let result = KeyPair::load(&key_path, &pub_path);
        assert!(result.is_err());
    }

    #[test]
    fn load_rejects_pub_mismatch() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("a.key");
        let pub_path = dir.path().join("a.pub");
        let _ = KeyPair::generate_to(&key_path, &pub_path).unwrap();
        // Overwrite pubkey (as root of test) — need to restore write perm first
        let mut perms = fs::metadata(&pub_path).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o644);
        fs::set_permissions(&pub_path, perms).unwrap();
        fs::write(&pub_path, [0u8; 32]).unwrap();
        let result = KeyPair::load(&key_path, &pub_path);
        assert!(result.is_err());
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("rt.key");
        let pub_path = dir.path().join("rt.pub");
        let kp = KeyPair::generate_to(&key_path, &pub_path).unwrap();
        let digest = [42u8; 32];
        let sig = kp.sign(&digest);
        verify_with_pub(&kp.public_bytes(), &digest, &sig).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("tam.key");
        let pub_path = dir.path().join("tam.pub");
        let kp = KeyPair::generate_to(&key_path, &pub_path).unwrap();
        let digest = [42u8; 32];
        let mut sig = kp.sign(&digest);
        sig[0] ^= 0xFF;
        let result = verify_with_pub(&kp.public_bytes(), &digest, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn key_id_is_deterministic() {
        let dir = tempdir().unwrap();
        let kp =
            KeyPair::generate_to(&dir.path().join("d.key"), &dir.path().join("d.pub")).unwrap();
        assert_eq!(kp.key_id_hex(), kp.key_id_hex());
        assert_eq!(kp.key_id_hex().len(), 64);
    }
}
