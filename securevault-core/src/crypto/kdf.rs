//! Key Derivation Functions
//!
//! Implements:
//! - Argon2id (memory-hard KDF for master password)
//! - HKDF (HMAC-based KDF for key expansion)

use argon2::{password_hash::SaltString, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{Error, Result};

/// Argon2id parameters
#[derive(Debug, Clone)]
pub struct Argon2Params {
    pub memory: u32,      // Memory in KB (e.g., 65536 = 64MB)
    pub iterations: u32,   // Number of iterations
    pub parallelism: u32,  // Number of lanes
    pub salt_len: usize,  // Salt length in bytes
    pub output_len: usize, // Derived key length
}

impl Default for Argon2Params {
    fn default() -> Self {
        // Enhanced for post-quantum security - high memory cost against GPU attacks
        // m=262144 (256MB), t=4, p=4 - significantly stronger than OWASP defaults
        Self {
            memory: 262144,    // 256 MB - high memory cost for GPU/ASIC resistance
            iterations: 4,     // 4 iterations - increased from 3
            parallelism: 4,     // 4 lanes
            salt_len: 32,      // 32 bytes - increased from 16
            output_len: 32,    // 256-bit key
        }
    }
}

/// Derive a key from password using Argon2id
/// 
/// # Arguments
/// * `password` - The master password
/// * `salt` - Optional salt (will be generated if None)
/// * `params` - Argon2 parameters
/// 
/// # Returns
/// * `(derived_key, salt)` - The derived key and the salt used
pub fn derive_key_argon2(
    password: &str,
    salt: Option<&[u8]>,
    params: &Argon2Params,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let salt = match salt {
        Some(s) => {
            if s.len() != params.salt_len {
                return Err(Error::Crypto(format!("Invalid salt length: {}", s.len())));
            }
            s.to_vec()
        }
        None => {
            // Generate random salt
            use crate::crypto::rng::random_bytes;
            random_bytes(params.salt_len)?
        }
    };

    // Create Argon2 instance
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.memory,
            params.iterations,
            params.parallelism,
            Some(params.output_len),
        )
        .map_err(|e| Error::Crypto(format!("Invalid Argon2 params: {}", e)))?,
    );

    // Derive key
    let mut output = vec![0u8; params.output_len];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut output)
        .map_err(|e| Error::Crypto(format!("Argon2 key derivation failed: {}", e)))?;

    Ok((output, salt))
}

/// Derive a key using HKDF (HMAC-based Key Derivation Function)
/// 
/// # Arguments
/// * `ikm` - Input Key Material
/// * `salt` - Optional salt (uses default if None)
/// * `info` - Optional context info
/// * `output_len` - Desired output length
/// 
/// # Returns
/// * `derived_key` - The derived key
pub fn derive_key_hkdf(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
    output_len: usize,
) -> Result<Vec<u8>> {
    type HmacSha256 = Hmac<Sha256>;
    
    let salt = salt.unwrap_or(b"PVault-HKDF-Salt".as_slice());
    
    // Create HMAC from salt
    let mut mac = HmacSha256::new_from_slice(salt)
        .map_err(|e| Error::Crypto(format!("Invalid HMAC key: {}", e)))?;
    
    // Hash the IKM
    mac.update(ikm);
    let prk = mac.finalize().into_bytes();

    // Expand using HKDF-Expand
    let mut okm = Vec::with_capacity(output_len);
    let mut t = Vec::new();
    let mut counter: u8 = 1;

    while okm.len() < output_len {
        let mut mac = HmacSha256::new_from_slice(&prk)
            .map_err(|e| Error::Crypto(format!("Invalid HMAC key: {}", e)))?;
        
        mac.update(&t);
        if let Some(i) = info {
            mac.update(i);
        }
        mac.update(&[counter]);
        
        t = mac.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&t);
        counter += 1;
    }

    okm.truncate(output_len);
    Ok(okm)
}

/// Derive multiple keys from a single master key (key separation)
/// 
/// # Arguments
/// * `master_key` - The master key
/// * `context` - Context string for key separation (e.g., "vault", "totp")
/// 
/// # Returns
/// * `derived_key` - Context-specific derived key
pub fn derive_context_key(master_key: &[u8], context: &str) -> Result<Vec<u8>> {
    derive_key_hkdf(master_key, None, Some(context.as_bytes()), 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_derive() {
        let password = "test_password_123";
        let params = Argon2Params::default();
        
        let (key, salt) = derive_key_argon2(password, None, &params).unwrap();
        
        assert_eq!(key.len(), 32);
        assert_eq!(salt.len(), 16);
        
        // Verify deterministic: same password + same salt = same key
        let (key2, _) = derive_key_argon2(password, Some(&salt), &params).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_hkdf_derive() {
        let ikm = b"input_key_material";
        
        let key = derive_key_hkdf(ikm, None, Some(b"test-info"), 32).unwrap();
        
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_context_key() {
        let master = [0u8; 32];
        
        let vault_key = derive_context_key(&master, "vault").unwrap();
        let totp_key = derive_context_key(&master, "totp").unwrap();
        
        // Different contexts should produce different keys
        assert_ne!(vault_key, totp_key);
        
        // Same context should produce same key
        let vault_key2 = derive_context_key(&master, "vault").unwrap();
        assert_eq!(vault_key, vault_key2);
    }
}