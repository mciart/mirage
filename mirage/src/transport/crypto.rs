//! Application-layer encryption for framed packets.
//!
//! Provides `FrameCipher` which wraps ChaCha20-Poly1305 AEAD encryption
//! for encrypting DATA frame payloads. This protects VPN traffic against
//! CDN TLS stripping — even if the outer TLS is terminated by a CDN,
//! the inner payload remains encrypted.
//!
//! ## Nonce Management
//!
//! Each cipher uses a simple 96-bit counter nonce (12 bytes):
//! - Bytes 0-7: 64-bit little-endian counter (incremented per frame)
//! - Bytes 8-11: zeros (reserved)
//!
//! Nonce uniqueness is guaranteed by using **directional key pairs**:
//! client-to-server and server-to-client each use a separate derived key,
//! so even with identical counter values, the (key, nonce) pair is unique.
//!
//! ## Key Derivation
//!
//! The user-provided `inner_key` is expanded via HKDF-SHA256 into two keys:
//! ```text
//! salt = "mirage-inner-v1"
//! c2s_key = HKDF-Expand(HKDF-Extract(salt, inner_key), "mirage-c2s", 32)
//! s2c_key = HKDF-Expand(HKDF-Extract(salt, inner_key), "mirage-s2c", 32)
//! ```

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// Authentication tag size for ChaCha20-Poly1305 (16 bytes)
pub const TAG_SIZE: usize = 16;

const HKDF_SALT: &[u8] = b"mirage-inner-v1";
const HKDF_INFO_C2S: &[u8] = b"mirage-c2s";
const HKDF_INFO_S2C: &[u8] = b"mirage-s2c";

/// Derives a directional key pair from a user-provided password string.
///
/// Returns `(c2s_key, s2c_key)`:
/// - `c2s_key`: used by client writer + server reader
/// - `s2c_key`: used by server writer + client reader
pub fn derive_key_pair(inner_key: &str) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), inner_key.as_bytes());

    let mut c2s_key = [0u8; 32];
    hk.expand(HKDF_INFO_C2S, &mut c2s_key)
        .expect("HKDF expand should not fail for 32 bytes");

    let mut s2c_key = [0u8; 32];
    hk.expand(HKDF_INFO_S2C, &mut s2c_key)
        .expect("HKDF expand should not fail for 32 bytes");

    (c2s_key, s2c_key)
}

/// AEAD cipher for encrypting/decrypting individual frame payloads.
///
/// Uses a simple counter nonce. Nonce uniqueness across directions is
/// guaranteed by using separate keys for client→server and server→client.
pub struct FrameCipher {
    cipher: ChaCha20Poly1305,
    /// Nonce counter (incremented per encrypt/decrypt call)
    counter: u64,
}

impl FrameCipher {
    /// Creates a new FrameCipher from a 32-byte derived key.
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher =
            ChaCha20Poly1305::new_from_slice(key).expect("ChaCha20Poly1305 key should be 32 bytes");

        Self { cipher, counter: 0 }
    }

    /// Builds a 12-byte nonce from the counter.
    fn build_nonce(counter: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&counter.to_le_bytes());
        *Nonce::from_slice(&nonce_bytes)
    }

    /// Encrypts a plaintext payload with the given AAD (frame header).
    ///
    /// Returns ciphertext + 16-byte auth tag appended.
    /// Increments the internal counter.
    pub fn encrypt(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let nonce = Self::build_nonce(self.counter);
        self.counter += 1;

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        self.cipher
            .encrypt(&nonce, payload)
            .map_err(|_| EncryptionError::EncryptFailed)
    }

    /// Decrypts a ciphertext payload (with appended auth tag) using the given AAD.
    ///
    /// Returns the plaintext if authentication succeeds.
    /// Increments the internal counter.
    pub fn decrypt(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if ciphertext.len() < TAG_SIZE {
            return Err(EncryptionError::CiphertextTooShort);
        }

        let nonce = Self::build_nonce(self.counter);
        self.counter += 1;

        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        self.cipher
            .decrypt(&nonce, payload)
            .map_err(|_| EncryptionError::DecryptFailed)
    }

    /// Returns the current counter (for diagnostics).
    pub fn counter(&self) -> u64 {
        self.counter
    }
}

impl Drop for FrameCipher {
    fn drop(&mut self) {
        self.counter = 0;
    }
}

/// Errors that can occur during frame encryption/decryption.
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("Encryption failed")]
    EncryptFailed,
    #[error("Decryption failed (key mismatch or tampered data)")]
    DecryptFailed,
    #[error("Ciphertext too short for auth tag")]
    CiphertextTooShort,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_pair_deterministic() {
        let (c2s_1, s2c_1) = derive_key_pair("test-password-123");
        let (c2s_2, s2c_2) = derive_key_pair("test-password-123");
        assert_eq!(c2s_1, c2s_2);
        assert_eq!(s2c_1, s2c_2);

        // Two directions must have different keys
        assert_ne!(c2s_1, s2c_1);

        // Different password → different keys
        let (c2s_3, _) = derive_key_pair("different-password");
        assert_ne!(c2s_1, c2s_3);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (c2s_key, _s2c_key) = derive_key_pair("my-secret-key");

        // Client writer and server reader use the SAME c2s_key
        let mut writer = FrameCipher::new(&c2s_key);
        let mut reader = FrameCipher::new(&c2s_key);

        let aad = [0x00, 0x00, 0x0A]; // DATA frame header
        let plaintext = b"Hello, World! This is a test packet.";

        let ciphertext = writer.encrypt(&aad, plaintext).unwrap();
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        let decrypted = reader.decrypt(&aad, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_bidirectional_keys() {
        let (c2s_key, s2c_key) = derive_key_pair("bidirectional-test");

        // Client→Server direction
        let mut client_writer = FrameCipher::new(&c2s_key);
        let mut server_reader = FrameCipher::new(&c2s_key);

        // Server→Client direction
        let mut server_writer = FrameCipher::new(&s2c_key);
        let mut client_reader = FrameCipher::new(&s2c_key);

        let aad = [0x00, 0x00, 0x05];

        // Client sends to server
        let ct1 = client_writer.encrypt(&aad, b"hello server").unwrap();
        let pt1 = server_reader.decrypt(&aad, &ct1).unwrap();
        assert_eq!(&pt1, b"hello server");

        // Server sends to client
        let ct2 = server_writer.encrypt(&aad, b"hello client").unwrap();
        let pt2 = client_reader.decrypt(&aad, &ct2).unwrap();
        assert_eq!(&pt2, b"hello client");
    }

    #[test]
    fn test_wrong_key_fails() {
        let (c2s_key1, _) = derive_key_pair("correct-key");
        let (c2s_key2, _) = derive_key_pair("wrong-key");

        let mut writer = FrameCipher::new(&c2s_key1);
        let mut reader = FrameCipher::new(&c2s_key2);

        let aad = [0x00, 0x00, 0x0A];
        let ciphertext = writer.encrypt(&aad, b"secret data").unwrap();

        assert!(reader.decrypt(&aad, &ciphertext).is_err());
    }

    #[test]
    fn test_cross_direction_fails() {
        let (c2s_key, s2c_key) = derive_key_pair("cross-test");

        // Encrypt with c2s key, try to decrypt with s2c key → must fail
        let mut writer = FrameCipher::new(&c2s_key);
        let mut reader = FrameCipher::new(&s2c_key);

        let aad = [0x00, 0x00, 0x05];
        let ciphertext = writer.encrypt(&aad, b"wrong direction").unwrap();

        assert!(reader.decrypt(&aad, &ciphertext).is_err());
    }

    #[test]
    fn test_tampered_aad_fails() {
        let (c2s_key, _) = derive_key_pair("test-key");
        let mut writer = FrameCipher::new(&c2s_key);
        let mut reader = FrameCipher::new(&c2s_key);

        let aad = [0x00, 0x00, 0x0A];
        let ciphertext = writer.encrypt(&aad, b"important data").unwrap();

        // Tamper with AAD
        let bad_aad = [0x01, 0x00, 0x0A];
        assert!(reader.decrypt(&bad_aad, &ciphertext).is_err());
    }

    #[test]
    fn test_nonce_counter_increment() {
        let (c2s_key, _) = derive_key_pair("counter-test");
        let mut cipher = FrameCipher::new(&c2s_key);

        let aad = [0x00, 0x00, 0x05];
        for i in 0..10u64 {
            assert_eq!(cipher.counter(), i);
            cipher.encrypt(&aad, b"data").unwrap();
        }
        assert_eq!(cipher.counter(), 10);
    }
}
