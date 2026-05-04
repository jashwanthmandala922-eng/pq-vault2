//! Vault-level encryption utilities

use crate::error::Result;

/// Vault encryption context
pub struct VaultCrypto {
    pub session_key: Vec<u8>,
}

impl VaultCrypto {
    /// Create new vault crypto context
    pub fn new(session_key: Vec<u8>) -> Self {
        Self { session_key }
    }

    /// Get the session key as 32-byte array
    pub fn key_array(&self) -> Result<[u8; 32]> {
        if self.session_key.len() != 32 {
            return Err(crate::error::Error::Crypto("Invalid session key length".to_string()));
        }
        
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.session_key);
        Ok(arr)
    }
}

impl Drop for VaultCrypto {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.session_key.zeroize();
    }
}