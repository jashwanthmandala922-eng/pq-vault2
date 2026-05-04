//! AES-256-GCM Encryption
//!
//! Implements AES-256-GCM (Galois/Counter Mode) for authenticated encryption

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// AES-256 key type
pub type AeadKey = [u8; 32];

/// AES-GCM nonce (96-bit)
pub type AeadNonce = [u8; 12];

/// Size constants
pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

/// Encrypt data with AES-256-GCM
/// 
/// Returns: nonce (12 bytes) + ciphertext + auth tag (16 bytes)
pub fn encrypt_aes_256_gcm(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &AeadNonce,
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::Crypto(format!("Invalid AES key: {}", e)))?;
    
    let nonce = Nonce::from_slice(nonce);
    
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::Crypto(format!("AES encryption failed: {}", e)))?;
    
    Ok(ciphertext)
}

/// Decrypt data with AES-256-GCM
/// 
/// Input: ciphertext + auth tag (16 bytes)
pub fn decrypt_aes_256_gcm(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &AeadNonce,
) -> Result<Vec<u8>> {
    if ciphertext.len() < TAG_SIZE {
        return Err(Error::Crypto("Ciphertext too short".to_string()));
    }
    
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::Crypto(format!("Invalid AES key: {}", e)))?;
    
    let nonce = Nonce::from_slice(nonce);
    
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::Crypto("Decryption failed - invalid key or corrupted data".to_string()))?;
    
    Ok(plaintext)
}

/// Encrypt data with AES-256-GCM using a generic key slice
pub fn encrypt_with_key(plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    if key.len() != KEY_SIZE {
        return Err(Error::Crypto(format!("Invalid key size: {}", key.len())));
    }
    if nonce.len() != NONCE_SIZE {
        return Err(Error::Crypto(format!("Invalid nonce size: {}", nonce.len())));
    }
    
    let mut key_array = [0u8; KEY_SIZE];
    let mut nonce_array = [0u8; NONCE_SIZE];
    key_array.copy_from_slice(key);
    nonce_array.copy_from_slice(nonce);
    
    encrypt_aes_256_gcm(plaintext, &key_array, &nonce_array)
}

/// Decrypt data with AES-256-GCM using a generic key slice
pub fn decrypt_with_key(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    if key.len() != KEY_SIZE {
        return Err(Error::Crypto(format!("Invalid key size: {}", key.len())));
    }
    if nonce.len() != NONCE_SIZE {
        return Err(Error::Crypto(format!("Invalid nonce size: {}", nonce.len())));
    }
    
    let mut key_array = [0u8; KEY_SIZE];
    let mut nonce_array = [0u8; NONCE_SIZE];
    key_array.copy_from_slice(key);
    nonce_array.copy_from_slice(nonce);
    
    decrypt_aes_256_gcm(ciphertext, &key_array, &nonce_array)
}

/// Zeroize helper for secure memory clearing
pub fn zeroize(data: &mut [u8]) {
    data.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> AeadKey {
        [0u8; 32]
    }

    fn test_nonce() -> AeadNonce {
        [0u8; 12]
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"Hello, World!";
        
        let ciphertext = encrypt_aes_256_gcm(plaintext, &key, &nonce).unwrap();
        let decrypted = decrypt_aes_256_gcm(&ciphertext, &key, &nonce).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_different_nonces() {
        let key = test_key();
        let plaintext = b"Test message";
        
        let nonce1 = [1u8; 12];
        let nonce2 = [2u8; 12];
        
        let ciphertext1 = encrypt_aes_256_gcm(plaintext, &key, &nonce1).unwrap();
        let ciphertext2 = encrypt_aes_256_gcm(plaintext, &key, &nonce2).unwrap();
        
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let nonce = test_nonce();
        let plaintext = b"Secret data";
        
        let ciphertext = encrypt_aes_256_gcm(plaintext, &key1, &nonce).unwrap();
        let result = decrypt_aes_256_gcm(&ciphertext, &key2, &nonce);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"Important message";
        
        let mut ciphertext = encrypt_aes_256_gcm(plaintext, &key, &nonce).unwrap();
        ciphertext[0] ^= 0xFF; // Tamper with ciphertext
        
        let result = decrypt_aes_256_gcm(&ciphertext, &key, &nonce);
        
        assert!(result.is_err());
    }
}