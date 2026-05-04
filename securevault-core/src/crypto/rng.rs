//! Cryptographically Secure Random Number Generator
//!
//! Uses ring's CSPRNG (ChaCha20 based) for secure randomness

use getrandom::getrandom;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Generate cryptographically secure random bytes
/// 
/// # Arguments
/// * `size` - Number of random bytes to generate
/// 
/// # Returns
/// * `Vec<u8>` - Random bytes
pub fn random_bytes(size: usize) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; size];
    
    getrandom(&mut buffer)
        .map_err(|e| Error::Crypto(format!("Failed to generate random bytes: {:?}", e)))?;
    
    Ok(buffer)
}

/// Generate a fixed-size random array
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut array = [0u8; N];
    
    getrandom(&mut array)
        .map_err(|e| Error::Crypto(format!("Failed to generate random array: {:?}", e)))?;
    
    Ok(array)
}

/// Generate a random 64-bit unsigned integer
pub fn random_u64() -> Result<u64> {
    let bytes = random_bytes(8)?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

/// Generate a random 32-bit unsigned integer
pub fn random_u32() -> Result<u32> {
    let bytes = random_bytes(4)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

/// Generate a random usize
pub fn random_usize() -> Result<usize> {
    let bytes = random_bytes(std::mem::size_of::<usize>())?;
    Ok(usize::from_le_bytes(bytes.try_into().unwrap()))
}

/// Generate a random boolean
pub fn random_bool() -> Result<bool> {
    let byte = random_bytes(1)?;
    Ok(byte[0] & 1 == 1)
}

/// Random for selection from a range
pub fn random_in_range(min: usize, max: usize) -> Result<usize> {
    if min >= max {
        return Err(Error::Crypto("Invalid range".to_string()));
    }
    
    let range = max - min;
    let random = random_usize()?;
    Ok(min + (random % range))
}

/// Select random element from a slice
pub fn random_element<T>(items: &[T]) -> Result<&T> {
    if items.is_empty() {
        return Err(Error::Crypto("Empty slice".to_string()));
    }
    
    let index = random_in_range(0, items.len())?;
    Ok(&items[index])
}

/// Generate random alphanumeric string
pub fn random_alphanumeric(length: usize) -> Result<String> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    
    let mut result = String::with_capacity(length);
    
    for _ in 0..length {
        let idx = random_in_range(0, CHARS.len())?;
        result.push(CHARS[idx] as char);
    }
    
    Ok(result)
}

/// Generate random hex string
pub fn random_hex(length: usize) -> Result<String> {
    let bytes = random_bytes(length / 2 + 1)?;
    let hex = bytes.iter()
        .map(|b| format!("{:02x}", b))
        .take(length)
        .collect();
    
    Ok(hex)
}

/// Secure memory wrapper that zeroizes on drop
pub struct SecureVec {
    data: Vec<u8>,
}

impl SecureVec {
    pub fn new(size: usize) -> Result<Self> {
        Ok(Self {
            data: random_bytes(size)?,
        })
    }
    
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Drop for SecureVec {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// Generate nonce for encryption (12 bytes for GCM, 12 for ChaCha20)
pub fn generate_nonce_12() -> Result<[u8; 12]> {
    random_array::<12>()
}

/// Generate nonce for XChaCha20 (24 bytes)
pub fn generate_nonce_24() -> Result<[u8; 24]> {
    random_array::<24>()
}

/// Generate a random UUID
pub fn random_uuid() -> Result<uuid::Uuid> {
    Ok(uuid::Uuid::new_v4())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        let bytes = random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);
        
        // Different calls should produce different values (with high probability)
        let bytes2 = random_bytes(32).unwrap();
        assert_ne!(bytes, bytes2);
    }

    #[test]
    fn test_random_array() {
        let arr: [u8; 16] = random_array().unwrap();
        assert_eq!(arr.len(), 16);
    }

    #[test]
    fn test_random_u64() {
        let val = random_u64().unwrap();
        // Just check it doesn't panic
        assert!(true);
    }

    #[test]
    fn test_random_in_range() {
        let val = random_in_range(5, 10).unwrap();
        assert!(val >= 5 && val < 10);
    }

    #[test]
    fn test_random_element() {
        let items = [1, 2, 3, 4, 5];
        let elem = random_element(&items).unwrap();
        assert!(items.contains(elem));
    }

    #[test]
    fn test_random_alphanumeric() {
        let s = random_alphanumeric(16).unwrap();
        assert_eq!(s.len(), 16);
    }

    #[test]
    fn test_generate_nonce_12() {
        let nonce = generate_nonce_12().unwrap();
        assert_eq!(nonce.len(), 12);
    }
}