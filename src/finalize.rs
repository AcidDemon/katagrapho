//! RAII guard ensuring `age::Encryptor::finish()` runs on every exit path,
//! including signals. The bug it fixes: in the previous code,
//! `encryptor.finish()` was only called when `stream_stdin` returned Ok,
//! so a SIGTERM mid-stream left an unfinalized (undecryptable) age blob.

use std::io::{self, Write};

/// Wraps an age stream writer and guarantees `finish()` runs once, on
/// drop or explicit `finish()`. The result of `finish()` from drop is
/// swallowed; callers who care must call the explicit `finish()`.
pub struct EncryptionFinalizer<W: Write> {
    inner: Option<age::stream::StreamWriter<W>>,
}

impl<W: Write> EncryptionFinalizer<W> {
    pub fn new(writer: age::stream::StreamWriter<W>) -> Self {
        Self { inner: Some(writer) }
    }

    /// Run finish() now and return its result. After this call, drop is a no-op.
    pub fn finish(mut self) -> io::Result<()> {
        match self.inner.take() {
            Some(w) => w.finish().map(|_| ()),
            None => Ok(()),
        }
    }
}

impl<W: Write> Write for EncryptionFinalizer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.inner.as_mut() {
            Some(w) => w.write(buf),
            None => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "finalizer drained",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.inner.as_mut() {
            Some(w) => w.flush(),
            None => Ok(()),
        }
    }
}

impl<W: Write> Drop for EncryptionFinalizer<W> {
    fn drop(&mut self) {
        if let Some(w) = self.inner.take() {
            // Best effort: swallow result. Callers who care call finish() explicitly.
            let _ = w.finish();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::x25519::Identity;
    use std::io::{Cursor, Read};

    fn round_trip(plaintext: &[u8], finalize_explicitly: bool) -> Vec<u8> {
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let mut buf: Vec<u8> = Vec::new();
        {
            let encryptor = age::Encryptor::with_recipients(
                std::iter::once(&recipient as &dyn age::Recipient),
            )
            .unwrap();
            let inner = encryptor.wrap_output(&mut buf).unwrap();
            let mut fin = EncryptionFinalizer::new(inner);
            fin.write_all(plaintext).unwrap();
            if finalize_explicitly {
                fin.finish().unwrap();
            }
            // else: drop runs the finalize
        }
        // Decrypt
        let decryptor = age::Decryptor::new(Cursor::new(buf)).unwrap();
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .unwrap();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn explicit_finish_produces_decryptable_blob() {
        let pt = b"hello world";
        assert_eq!(round_trip(pt, true), pt);
    }

    #[test]
    fn drop_also_finalizes() {
        let pt = b"hello via drop";
        assert_eq!(round_trip(pt, false), pt);
    }
}
