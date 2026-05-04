//! Cryptographic Operations Module
//!
//! Provides:
//! - AES-256-GCM encryption
//! - ChaCha20-Poly1305 encryption
//! - Argon2id key derivation
//! - ML-KEM (Kyber) post-quantum key encapsulation
//! - ML-DSA (Dilithium) post-quantum signatures
//! - SHA-3 hashing
//! - CSPRNG

pub mod aes;
pub mod chacha20;
pub mod kdf;
pub mod ml_kem;
pub mod ml_dsa;
pub mod sha3;
pub mod rng;

pub use aes::{encrypt_aes_256_gcm, decrypt_aes_256_gcm, AeadKey, AeadNonce};
pub use chacha20::{encrypt_chacha20poly1305, decrypt_chacha20poly1305};
pub use kdf::{derive_key_argon2, derive_key_hkdf, Argon2Params};
pub use ml_kem::{MLKEM768, MLKEM1024};
pub use ml_dsa::{MLDSA44, MLDSA65, MLDSA87};
pub use sha3::{sha3_256, sha3_512, shake256, SHA3_256_LEN, SHA3_512_LEN};
pub use rng::{random_bytes, random_in_range, random_element, generate_nonce_12, generate_nonce_24};

/// Size constants
pub const AES_256_KEY_SIZE: usize = 32;
pub const AES_GCM_NONCE_SIZE: usize = 12;
pub const CHACHA20_KEY_SIZE: usize = 32;
pub const CHACHA20_NONCE_SIZE: usize = 12;
pub const SHA3_256_SIZE: usize = 32;
pub const SHA3_512_SIZE: usize = 64;
pub const ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1184;
pub const ML_KEM_768_SECRET_KEY_SIZE: usize = 2400;
pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;
pub const ML_DSA_65_SECRET_KEY_SIZE: usize = 4000;
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3293;

// ML-KEM-1024 (Security Category 5 - 192-bit)
pub const ML_KEM_1024_PUBLIC_KEY_SIZE: usize = 1568;
pub const ML_KEM_1024_SECRET_KEY_SIZE: usize = 3168;
pub const ML_KEM_1024_CIPHERTEXT_SIZE: usize = 1568;

// ML-DSA-87 (Security Category 5 - 256-bit)
pub const ML_DSA_87_PUBLIC_KEY_SIZE: usize = 2592;
pub const ML_DSA_87_SECRET_KEY_SIZE: usize = 4896;
pub const ML_DSA_87_SIGNATURE_SIZE: usize = 4595;

use crate::error::{Error, Result};

/// Encrypt data with AES-256-GCM
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let nonce = rng::random_bytes(AES_GCM_NONCE_SIZE)?;
    let ciphertext = aes::encrypt_aes_256_gcm(plaintext, key, &nonce)?;
    
    // Prepend nonce to ciphertext
    let mut result = nonce.to_vec();
    result.extend(ciphertext);
    Ok(result)
}

/// Decrypt data with AES-256-GCM
pub fn decrypt(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if ciphertext.len() < AES_GCM_NONCE_SIZE {
        return Err(Error::Crypto("Ciphertext too short".to_string()));
    }
    
    let (nonce, encrypted_data) = ciphertext.split_at(AES_GCM_NONCE_SIZE);
    let nonce_array: [u8; AES_GCM_NONCE_SIZE] = nonce.try_into()
        .map_err(|_| Error::Crypto("Invalid nonce size".to_string()))?;
    
    aes::decrypt_aes_256_gcm(encrypted_data, key, &nonce_array)
}

/// Generate a random encryption key
pub fn generate_key() -> Result<[u8; 32]> {
    let bytes = rng::random_bytes(32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = generate_key().unwrap();
        let plaintext = b"Hello, SecureVault!";
        
        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_different_nonces() {
        let key = generate_key().unwrap();
        let plaintext = b"Test message";
        
        let encrypted1 = encrypt(plaintext, &key).unwrap();
        let encrypted2 = encrypt(plaintext, &key).unwrap();
        
        // Different nonces should produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);
    }
}