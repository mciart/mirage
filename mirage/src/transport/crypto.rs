//! Application-layer encryption for framed packets.
//!
//! Provides `FrameCipher` which wraps ChaCha20-Poly1305 AEAD encryption
//! for encrypting DATA frame payloads. This protects VPN traffic against
//! CDN TLS stripping — even if the outer TLS is terminated by a CDN,
//! the inner payload remains encrypted.
//!
//! ## Nonce Management
//!
//! Each direction (read/write) maintains an independent 96-bit nonce counter:
//! - Bytes 0-3: random IV (generated per cipher instance)
//! - Bytes 4-11: 64-bit little-endian counter (incremented per frame)
//!
//! ## Key Derivation
//!
//! The user-provided `inner_key` is expanded via HKDF-SHA256:
//! ```text
//! salt = "mirage-inner-v1"
//! info = "mirage-chacha20-poly1305"
//! derived_key = HKDF-Expand(HKDF-Extract(salt, inner_key), info, 32)
//! ```

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// Authentication tag size for ChaCha20-Poly1305 (16 bytes)
pub const TAG_SIZE: usize = 16;

const HKDF_SALT: &[u8] = b"mirage-inner-v1";
const HKDF_INFO: &[u8] = b"mirage-chacha20-poly1305";

/// Derives a 32-byte encryption key from a user-provided password string.
pub fn derive_key(inner_key: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), inner_key.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .expect("HKDF expand should not fail for 32 bytes");
    key
}

/// AEAD cipher for encrypting/decrypting individual frame payloads.
///
/// Maintains separate nonce counters for encryption and decryption,
/// ensuring each frame uses a unique nonce.
pub struct FrameCipher {
    cipher: ChaCha20Poly1305,
    /// Random IV prefix (4 bytes), set once at construction
    iv_prefix: [u8; 4],
    /// Encryption nonce counter (incremented per encrypt call)
    encrypt_counter: u64,
    /// Decryption nonce counter (incremented per decrypt call)
    decrypt_counter: u64,
}

impl FrameCipher {
    /// Creates a new FrameCipher from a 32-byte derived key.
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher =
            ChaCha20Poly1305::new_from_slice(key).expect("ChaCha20Poly1305 key should be 32 bytes");

        // Generate random 4-byte IV prefix
        let mut iv_prefix = [0u8; 4];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut iv_prefix);

        Self {
            cipher,
            iv_prefix,
            encrypt_counter: 0,
            decrypt_counter: 0,
        }
    }

    /// Creates a paired cipher with the same key but a different random IV.
    /// Used so that the reader and writer have independent nonce sequences.
    pub fn new_reader(key: &[u8; 32]) -> Self {
        Self::new(key)
    }

    /// Builds a 12-byte nonce from IV prefix + counter.
    fn build_nonce(iv_prefix: &[u8; 4], counter: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(iv_prefix);
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        *Nonce::from_slice(&nonce_bytes)
    }

    /// Encrypts a plaintext payload with the given AAD (frame header).
    ///
    /// Returns ciphertext + 16-byte auth tag appended.
    /// Increments the internal encryption counter.
    pub fn encrypt(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let nonce = Self::build_nonce(&self.iv_prefix, self.encrypt_counter);
        self.encrypt_counter += 1;

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
    /// Increments the internal decryption counter.
    pub fn decrypt(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if ciphertext.len() < TAG_SIZE {
            return Err(EncryptionError::CiphertextTooShort);
        }

        let nonce = Self::build_nonce(&self.iv_prefix, self.decrypt_counter);
        self.decrypt_counter += 1;

        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        self.cipher
            .decrypt(&nonce, payload)
            .map_err(|_| EncryptionError::DecryptFailed)
    }

    /// Returns the current encryption counter (for diagnostics).
    pub fn encrypt_count(&self) -> u64 {
        self.encrypt_counter
    }
}

impl Drop for FrameCipher {
    fn drop(&mut self) {
        // Zeroize sensitive material
        self.iv_prefix.zeroize();
        self.encrypt_counter = 0;
        self.decrypt_counter = 0;
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
    fn test_derive_key_deterministic() {
        let key1 = derive_key("test-password-123");
        let key2 = derive_key("test-password-123");
        assert_eq!(key1, key2);

        let key3 = derive_key("different-password");
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = derive_key("my-secret-key");

        // Both sides derive the same key, but need paired nonce counters
        let mut writer_cipher = FrameCipher::new(&key);
        // Reader must use the SAME iv_prefix as writer for nonces to match
        let mut reader_cipher = FrameCipher {
            cipher: ChaCha20Poly1305::new_from_slice(&key).unwrap(),
            iv_prefix: writer_cipher.iv_prefix, // Copy IV from writer
            encrypt_counter: 0,
            decrypt_counter: 0,
        };

        let aad = [0x00, 0x00, 0x0A]; // DATA frame header
        let plaintext = b"Hello, World! This is a test packet.";

        let ciphertext = writer_cipher.encrypt(&aad, plaintext).unwrap();
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        let decrypted = reader_cipher.decrypt(&aad, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = derive_key("correct-key");
        let key2 = derive_key("wrong-key");

        let mut writer = FrameCipher::new(&key1);
        let mut reader = FrameCipher::new(&key2);

        let aad = [0x00, 0x00, 0x0A];
        let ciphertext = writer.encrypt(&aad, b"secret data").unwrap();

        assert!(reader.decrypt(&aad, &ciphertext).is_err());
    }

    #[test]
    fn test_tampered_aad_fails() {
        let key = derive_key("test-key");
        let mut writer = FrameCipher::new(&key);
        let mut reader = FrameCipher {
            cipher: ChaCha20Poly1305::new_from_slice(&key).unwrap(),
            iv_prefix: writer.iv_prefix,
            encrypt_counter: 0,
            decrypt_counter: 0,
        };

        let aad = [0x00, 0x00, 0x0A];
        let ciphertext = writer.encrypt(&aad, b"important data").unwrap();

        // Tamper with AAD
        let bad_aad = [0x01, 0x00, 0x0A];
        assert!(reader.decrypt(&bad_aad, &ciphertext).is_err());
    }

    #[test]
    fn test_nonce_counter_increment() {
        let key = derive_key("counter-test");
        let mut cipher = FrameCipher::new(&key);

        let aad = [0x00, 0x00, 0x05];
        for i in 0..10u64 {
            assert_eq!(cipher.encrypt_count(), i);
            cipher.encrypt(&aad, b"data").unwrap();
        }
        assert_eq!(cipher.encrypt_count(), 10);
    }
}
