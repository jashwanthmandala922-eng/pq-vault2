//! ChaCha20-Poly1305 Encryption
//!
//! Implements ChaCha20-Poly1305 AEAD for authenticated encryption

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// ChaCha20 key type
pub type ChaChaKey = [u8; 32];

/// ChaCha20-Poly1305 nonce (96-bit)
pub type ChaChaNonce = [u8; 12];

/// Size constants
pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

/// Encrypt data with ChaCha20-Poly1305
/// 
/// Returns: ciphertext + auth tag (16 bytes)
pub fn encrypt_chacha20poly1305(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &ChaChaNonce,
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| Error::Crypto(format!("Invalid ChaCha20 key: {}", e)))?;
    
    let nonce = Nonce::from_slice(nonce);
    
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::Crypto(format!("ChaCha20 encryption failed: {}", e)))?;
    
    Ok(ciphertext)
}

/// Decrypt data with ChaCha20-Poly1305
pub fn decrypt_chacha20poly1305(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &ChaChaNonce,
) -> Result<Vec<u8>> {
    if ciphertext.len() < TAG_SIZE {
        return Err(Error::Crypto("Ciphertext too short".to_string()));
    }
    
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| Error::Crypto(format!("Invalid ChaCha20 key: {}", e)))?;
    
    let nonce = Nonce::from_slice(nonce);
    
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::Crypto("Decryption failed - invalid key or corrupted data".to_string()))?;
    
    Ok(plaintext)
}

/// Encrypt data with ChaCha20-Poly1305 using generic slices
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
    
    encrypt_chacha20poly1305(plaintext, &key_array, &nonce_array)
}

/// Decrypt data with ChaCha20-Poly1305 using generic slices
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
    
    decrypt_chacha20poly1305(ciphertext, &key_array, &nonce_array)
}

/// Zeroize memory for secure clearing
pub fn zeroize(data: &mut [u8]) {
    data.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> ChaChaKey {
        [0u8; 32]
    }

    fn test_nonce() -> ChaChaNonce {
        [0u8; 12]
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"Hello, PQ Vault!";
        
        let ciphertext = encrypt_chacha20poly1305(plaintext, &key, &nonce).unwrap();
        let decrypted = decrypt_chacha20poly1305(&ciphertext, &key, &nonce).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_different_nonces_different_ciphertext() {
        let key = test_key();
        let plaintext = b"Test data";
        
        let nonce1 = [1u8; 12];
        let nonce2 = [2u8; 12];
        
        let ct1 = encrypt_chacha20poly1305(plaintext, &key, &nonce1).unwrap();
        let ct2 = encrypt_chacha20poly1305(plaintext, &key, &nonce2).unwrap();
        
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let nonce = test_nonce();
        let plaintext = b"Secret";
        
        let ciphertext = encrypt_chacha20poly1305(plaintext, &key1, &nonce).unwrap();
        let result = decrypt_chacha20poly1305(&ciphertext, &key2, &nonce);
        
        assert!(result.is_err());
    }
}