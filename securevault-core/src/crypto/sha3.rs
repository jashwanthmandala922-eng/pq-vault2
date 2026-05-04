//! SHA-3 and SHAKE Hashing
//!
//! Implements SHA3-256, SHA3-512, and SHAKE256

use sha3::{Digest, Sha3_256, Sha3_512, Shake256};

use crate::error::Result;

/// SHA3-256 output size
pub const SHA3_256_LEN: usize = 32;
/// SHA3-512 output size
pub const SHA3_512_LEN: usize = 64;

/// Compute SHA3-256 hash
pub fn sha3_256(data: &[u8]) -> [u8; SHA3_256_LEN] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; SHA3_256_LEN];
    output.copy_from_slice(&result);
    output
}

/// Compute SHA3-512 hash
pub fn sha3_512(data: &[u8]) -> [u8; SHA3_512_LEN] {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; SHA3_512_LEN];
    output.copy_from_slice(&result);
    output
}

/// Compute SHA3-256 hash and return as Vec
pub fn sha3_256_vec(data: &[u8]) -> Vec<u8> {
    sha3_256(data).to_vec()
}

/// Compute SHA3-512 hash and return as Vec
pub fn sha3_512_vec(data: &[u8]) -> Vec<u8> {
    sha3_512(data).to_vec()
}

/// SHAKE256 extendable output function
pub struct Shake256Reader {
    inner: Shake256,
}

impl Shake256Reader {
    /// Create new SHAKE256 reader
    pub fn new() -> Self {
        Self {
            inner: Shake256::new(),
        }
    }

    /// Update with data
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Read output bytes
    pub fn read(&mut self, output: &mut [u8]) {
        // Use finalize_xof for XOF, then read
        let mut hasher = std::mem::replace(&mut self.inner, Shake256::new());
        let result = hasher.finalize_xof();
        let len = output.len().min(result.len());
        output[..len].copy_from_slice(&result[..len]);
    }

    /// Read exact number of bytes
    pub fn read_bytes(&mut self, count: usize) -> Vec<u8> {
        let mut output = vec![0u8; count];
        self.read(&mut output);
        output
    }
}

impl Default for Shake256Reader {
    fn default() -> Self {
        Self::new()
    }
}

/// SHAKE256 for XOF output
pub fn shake256(data: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::new();
    hasher.update(data);
    let result = hasher.finalize_xof();
    result[..output_len.min(result.len())].to_vec()
}

/// Constant-time compare to prevent timing attacks
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}

/// Hash for URL matching in autofiller (constant-length for comparison)
pub fn hash_url(url: &str) -> [u8; 32] {
    sha3_256(url.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256() {
        let data = b"test data";
        let hash = sha3_256(data);
        
        assert_eq!(hash.len(), 32);
        
        // Deterministic
        let hash2 = sha3_256(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_sha3_512() {
        let data = b"test data";
        let hash = sha3_512(data);
        
        assert_eq!(hash.len(), 64);
    }

    #[test]
    def test_shake256() {
        let data = b"test";
        let output = shake256(data, 32);
        
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare(b"test", b"test"));
        assert!(!constant_time_compare(b"test", b"Test"));
        assert!(!constant_time_compare(b"test", b"test1"));
    }

    #[test]
    fn test_hash_url() {
        let url1 = "https://example.com/login";
        let url2 = "https://example.com/login";
        let url3 = "https://example.com/signup";
        
        let hash1 = hash_url(url1);
        let hash2 = hash_url(url2);
        let hash3 = hash_url(url3);
        
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
}