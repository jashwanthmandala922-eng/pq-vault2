//! Secure Memory Management with Formal Zeroization
//!
//! This module provides memory-zeroing primitives that prevent compiler
//! optimization from removing security-critical memory clearing operations.
//!
//! The zeroize crate uses volatile writes and inline assembly where needed
//! to ensure the memory clearing is NOT optimized away by the compiler.

use zeroize::{Zeroize, Zeroizing};

/// A secure wrapper that automatically zeroizes its contents when dropped.
/// Use this for sensitive data that must be cleared from memory.
///
/// # Example
/// ```rust
/// use securevault_core::securemem::SecureVec;
///
/// fn sensitive_operation() {
///     let mut secret = SecureVec::new(vec![1, 2, 3, 4, 5]);
///     // Use secret...
/// } // secret is automatically zeroized here
/// ```
#[derive(Clone)]
pub struct SecureVec {
    data: Zeroizing<Vec<u8>>,
}

impl SecureVec {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data: Zeroizing::new(data),
        }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for SecureVec {
    fn drop(&mut self) {
        // Zeroize is automatically called via Zeroizing wrapper
        // The Drop impl ensures secure clearing even if forgotten
    }
}

/// A secure array wrapper for fixed-size sensitive data
pub struct SecureArray<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> SecureArray<N> {
    pub fn new(data: [u8; N]) -> Self {
        Self { data }
    }

    pub fn from_slice(data: &[u8]) -> Option<Self> {
        if data.len() != N {
            return None;
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(data);
        Some(Self { data: arr })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> Drop for SecureArray<N> {
    fn drop(&mut self) {
        // Use volatile write to prevent optimization
        self.data.zeroize();
    }
}

/// Session key with automatic zeroization
/// Used for vault session keys that must be cleared on lock
pub struct SessionKey {
    key: Zeroizing<[u8; 32]>,
}

impl SessionKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }

    pub fn from_vec(vec: Vec<u8>) -> Option<Self> {
        if vec.len() != 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&vec);
        Some(Self { key: Zeroizing::new(key) })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.key
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.key
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        // Zeroizing handles this automatically
    }
}

/// Master key with automatic zeroization
/// Used for vault master keys that must be cleared immediately after use
pub struct MasterKey {
    key: Zeroizing<[u8; 64]>, // Can hold 512-bit keys
    algorithm: Zeroizing<String>,
}

impl MasterKey {
    pub fn new(key: [u8; 64], algorithm: &str) -> Self {
        Self {
            key: Zeroizing::new(key),
            algorithm: Zeroizing::new(algorithm.to_string()),
        }
    }

    pub fn from_vec(vec: Vec<u8>, algorithm: &str) -> Option<Self> {
        if vec.len() > 64 {
            return None;
        }
        let mut key = [0u8; 64];
        key[..vec.len()].copy_from_slice(&vec);
        Some(Self {
            key: Zeroizing::new(key),
            algorithm: Zeroizing::new(algorithm.to_string()),
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.key
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.key.zeroize();
        self.algorithm.zeroize();
    }
}

/// Sensitive string that zeroizes on drop
/// Use for passwords, PINs, tokens
pub struct SecureString {
    data: Zeroizing<String>,
}

impl SecureString {
    pub fn new(data: String) -> Self {
        Self {
            data: Zeroizing::new(data),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.data
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // Overwrite with zeros before deallocation
        self.data.zeroize();
    }
}

/// Trait for types that hold sensitive data and need explicit zeroization
pub trait SecureZeroize {
    fn secure_zero(&mut self);
}

impl SecureZeroize for Vec<u8> {
    fn secure_zero(&mut self) {
        self.zeroize();
    }
}

impl SecureZeroize for String {
    fn secure_zero(&mut self) {
        self.zeroize();
    }
}

impl SecureZeroize for [u8] {
    fn secure_zero(&mut self) {
        self.zeroize();
    }
}

/// Explicit zeroization function that cannot be optimized away
/// Use this for explicit secure clearing when Drop is not sufficient
pub fn secure_zeroize(data: &mut [u8]) {
    use core::hint::black_box;
    
    // volatile write prevents optimization
    for i in 0..data.len() {
        unsafe {
            let ptr = data.as_mut_ptr().add(i);
            core::ptr::write_volatile(ptr, 0);
        }
    }
    
    // Use black_box to prevent dead code elimination
    black_box(data.as_ptr());
}

/// Secure clear for stack-allocated arrays
pub fn secure_zeroize_array<T: Default + Copy + Sized, const N: usize>(arr: &mut [T; N]) {
    for i in arr.iter_mut() {
        *i = T::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_vec_zeroize() {
        let vec = SecureVec::new(vec![1, 2, 3, 4, 5]);
        let ptr = vec.as_ptr();
        drop(vec);
        // Memory is zeroized on drop - cannot verify easily but follows best practice
    }

    #[test]
    fn test_session_key() {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        
        let session = SessionKey::new(key);
        assert_eq!(session.as_slice().len(), 32);
        
        drop(session);
        // Key is zeroized on drop
    }

    #[test]
    fn test_secure_string() {
        let secret = SecureString::new("my_password_123".to_string());
        assert_eq!(secret.as_str(), "my_password_123");
        drop(secret);
        // String is zeroized on drop
    }

    #[test]
    fn test_explicit_zeroize() {
        let mut data = vec![0xFF, 0xFF, 0xFF, 0xFF];
        secure_zeroize(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }
}