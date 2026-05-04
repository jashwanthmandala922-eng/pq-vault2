//! ML-DSA (Dilithium) Post-Quantum Digital Signatures
//!
//! Implements ML-DSA (Dilithium) digital signatures using liboqs

use zeroize::Zeroize;
use crate::error::{Error, Result};

/// ML-DSA-65 (Dilithium-5) - 192-bit security - RECOMMENDED
pub struct MLDSA65;

impl MLDSA65 {
    /// Create a new ML-DSA-65 instance
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    /// Generate a signing key pair
    pub fn keygen() -> Result<(Vec<u8>, Vec<u8>)> {
        // Use liboqs directly via the sig module
        let sig = liboqs::sigs::MLDSA65::new()
            .map_err(|e| Error::Crypto(format!("ML-DSA-65 init: {:?}", e))?;
        
        let (vk, sk) = sig.generate_keypair()
            .map_err(|e| Error::Crypto(format!("ML-DSA-65 keygen: {:?}", e)))?;
        
        Ok((vk.to_vec(), sk.to_vec()))
    }

    /// Sign a message
    pub fn sign(message: &[u8], signing_key: &[u8]) -> Result<Vec<u8>> {
        let sig = liboqs::sigs::MLDSA65::new()
            .map_err(|e| Error::Crypto(format!("ML-DSA-65 init: {:?}", e))?;
        
        let sk = liboqs::common::ByteArray::from(signing_key);
        let msg = liboqs::common::ByteArray::from(message);
        
        let signature = sig.sign(&sk, &msg)
            .map_err(|e| Error::Crypto(format!("ML-DSA-65 sign: {:?}", e)))?;
        
        Ok(signature.to_vec())
    }

    /// Verify a signature
    pub fn verify(message: &[u8], signature: &[u8], verification_key: &[u8]) -> Result<bool> {
        let sig = liboqs::sigs::MLDSA65::new()
            .map_err(|e| Error::Crypto(format!("ML-DSA-65 init: {:?}", e))?;
        
        let vk = liboqs::common::ByteArray::from(verification_key);
        let msg = liboqs::common::ByteArray::from(message);
        let sig_bytes = liboqs::common::ByteArray::from(signature);
        
        match sig.verify(&vk, &msg, &sig_bytes) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get public key size
    pub fn public_key_size() -> usize {
        1952 // ML-DSA-65
    }

    /// Get secret key size
    pub fn secret_key_size() -> usize {
        4000 // ML-DSA-65
    }

    /// Get signature size
    pub fn signature_size() -> usize {
        3293 // ML-DSA-65
    }
}

/// ML-DSA Signing Key wrapper
#[derive(Clone)]
pub struct SigningKey {
    pub bytes: Vec<u8>,
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// ML-DSA Verification Key wrapper
#[derive(Clone)]
pub struct VerificationKey {
    pub bytes: Vec<u8>,
}

/// Convenience functions using ML-DSA-65 (recommended for PQ Vault)

/// Generate ML-DSA-65 signing key pair
pub fn ml_dsa_keygen() -> Result<(Vec<u8>, Vec<u8>)> {
    MLDSA65::keygen()
}

/// Sign a message with ML-DSA-65
pub fn ml_dsa_sign(message: &[u8], signing_key: &[u8]) -> Result<Vec<u8>> {
    MLDSA65::sign(message, signing_key)
}

/// Verify a signature with ML-DSA-65
pub fn ml_dsa_verify(message: &[u8], signature: &[u8], verification_key: &[u8]) -> Result<bool> {
    MLDSA65::verify(message, signature, verification_key)
}

/// PQ Vault hybrid signature with both classic and PQC
#[derive(Debug, Clone)]
pub struct HybridSignature {
    pub classic_sig: Vec<u8>,  // Placeholder for ECDSA
    pub pq_sig: Vec<u8>,        // ML-DSA-65
}

/// Create hybrid signature (for future compatibility)
pub fn hybrid_sign(
    message: &[u8],
    _classic_signing_key: &[u8],
    pq_signing_key: &[u8],
) -> Result<HybridSignature> {
    // Classic signature placeholder (would use ed25519 in production)
    let classic_sig = Vec::new();
    
    // PQ signature
    let pq_sig = ml_dsa_sign(message, pq_signing_key)?;
    
    Ok(HybridSignature {
        classic_sig,
        pq_sig,
    })
}

/// Verify hybrid signature
pub fn hybrid_verify(
    message: &[u8],
    signature: &HybridSignature,
    _classic_verify_key: &[u8],
    pq_verify_key: &[u8],
) -> Result<bool> {
    // For now, verify PQC only
    ml_dsa_verify(message, &signature.pq_sig, pq_verify_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires liboqs to be properly linked
    fn test_ml_dsa_keygen() {
        let (vk, sk) = ml_dsa_keygen().unwrap();
        
        assert_eq!(vk.len(), 1952);
        assert_eq!(sk.len(), 4000);
    }

    #[test]
    #[ignore] // Requires liboqs to be properly linked
    fn test_sign_verify() {
        let (vk, sk) = ml_dsa_keygen().unwrap();
        
        let message = b"Test message for PQ Vault";
        let signature = ml_dsa_sign(message, &sk).unwrap();
        
        assert!(signature.len() > 0);
        
        let valid = ml_dsa_verify(message, &signature, &vk).unwrap();
        assert!(valid);
    }

    #[test]
    #[ignore] // Requires liboqs to be properly linked
    fn test_invalid_signature() {
        let (vk, _sk) = ml_dsa_keygen().unwrap();
        
        let message = b"Original message";
        let wrong_message = b"Tampered message";
        
        let (_vk2, sk2) = ml_dsa_keygen().unwrap();
        let signature = ml_dsa_sign(message, &sk2).unwrap();
        
        // Try to verify with wrong message
        let valid = ml_dsa_verify(wrong_message, &signature, &vk).unwrap();
        
        assert!(!valid);
    }
}

/// ML-DSA-87 (Dilithium-7) - 256-bit security - MAXIMUM SECURITY
pub struct MLDSA87;

impl MLDSA87 {
    /// Create a new ML-DSA-87 instance
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    /// Generate a signing key pair (ML-DSA-87)
    pub fn keygen() -> Result<(Vec<u8>, Vec<u8>)> {
        let sig = liboqs::sigs::MLDSA87::new()
            .map_err(|e| Error::Crypto(format!("ML-DSA-87 init: {:?}", e)))?;
        
        let (vk, sk) = sig.generate_keypair()
            .map_err(|e| Error::Crypto(format!("ML-DSA-87 keygen: {:?}", e)))?;
        
        Ok((vk.to_vec(), sk.to_vec()))
    }

    /// Sign a message (ML-DSA-87)
    pub fn sign(message: &[u8], signing_key: &[u8]) -> Result<Vec<u8>> {
        let sig = liboqs::sigs::MLDSA87::new()
            .map_err(|e| Error::Crypto(format!("ML-DSA-87 init: {:?}", e)))?;
        
        let sk = liboqs::common::ByteArray::from(signing_key);
        let msg = liboqs::common::ByteArray::from(message);
        
        let signature = sig.sign(&sk, &msg)
            .map_err(|e| Error::Crypto(format!("ML-DSA-87 sign: {:?}", e)))?;
        
        Ok(signature.to_vec())
    }

    /// Verify a signature (ML-DSA-87)
    pub fn verify(message: &[u8], signature: &[u8], verification_key: &[u8]) -> Result<bool> {
        let sig = liboqs::sigs::MLDSA87::new()
            .map_err(|e| Error::Crypto(format!("ML-DSA-87 init: {:?}", e)))?;
        
        let vk = liboqs::common::ByteArray::from(verification_key);
        let msg = liboqs::common::ByteArray::from(message);
        let sig_bytes = liboqs::common::ByteArray::from(signature);
        
        match sig.verify(&vk, &msg, &sig_bytes) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get public key size
    pub fn public_key_size() -> usize {
        2592 // ML-DSA-87
    }

    /// Get secret key size
    pub fn secret_key_size() -> usize {
        4896 // ML-DSA-87
    }

    /// Get signature size
    pub fn signature_size() -> usize {
        4595 // ML-DSA-87
    }
}

/// Generate ML-DSA-87 key pair (maximum security)
pub fn ml_dsa_87_keygen() -> Result<(Vec<u8>, Vec<u8>)> {
    MLDSA87::keygen()
}

/// Sign with ML-DSA-87
pub fn ml_dsa_87_sign(message: &[u8], signing_key: &[u8]) -> Result<Vec<u8>> {
    MLDSA87::sign(message, signing_key)
}

/// Verify ML-DSA-87 signature
pub fn ml_dsa_87_verify(message: &[u8], signature: &[u8], verification_key: &[u8]) -> Result<bool> {
    MLDSA87::verify(message, signature, verification_key)
}

/// Hybrid signature scheme combining ML-DSA-65 + ML-DSA-87
/// Provides defense-in-depth with two security levels
pub struct HybridSignature;

impl HybridSignature {
    /// Create a new hybrid signature
    pub fn sign(message: &[u8], key_65: &[u8], key_87: &[u8]) -> Result<Vec<u8>> {
        // Sign with ML-DSA-65
        let sig_65 = MLDSA65::sign(message, key_65)?;
        
        // Sign with ML-DSA-87
        let sig_87 = MLDSA87::sign(message, key_87)?;
        
        // Combine signatures: [sig_65 length: 4 bytes][sig_65][sig_87]
        let mut combined = Vec::with_capacity(4 + sig_65.len() + sig_87.len());
        combined.extend_from_slice(&(sig_65.len() as u32).to_le_bytes());
        combined.extend(sig_65);
        combined.extend(sig_87);
        
        Ok(combined)
    }

    /// Verify hybrid signature (requires both signatures to be valid)
    pub fn verify(message: &[u8], signature: &[u8], vk_65: &[u8], vk_87: &[u8]) -> Result<bool> {
        if signature.len() < 4 {
            return Ok(false);
        }
        
        let len_65 = u32::from_le_bytes([
            signature[0], signature[1], signature[2], signature[3]
        ]) as usize;
        
        if signature.len() < 4 + len_65 {
            return Ok(false);
        }
        
        let sig_65 = &signature[4..4 + len_65];
        let sig_87 = &signature[4 + len_65..];
        
        let valid_65 = MLDSA65::verify(message, sig_65, vk_65)?;
        let valid_87 = MLDSA87::verify(message, sig_87, vk_87)?;
        
        Ok(valid_65 && valid_87)
    }
}

#[cfg(test)]
mod tests_ml_dsa_87 {
    use super::*;

    #[test]
    fn test_ml_dsa_87_keygen() {
        let (vk, sk) = MLDSA87::keygen().unwrap();
        
        assert_eq!(vk.len(), MLDSA87::public_key_size());
        assert_eq!(sk.len(), MLDSA87::secret_key_size());
    }

    #[test]
    fn test_ml_dsa_87_sign_verify() {
        let (vk, sk) = MLDSA87::keygen().unwrap();
        
        let message = b"Maximum security signature test";
        let signature = MLDSA87::sign(message, &sk).unwrap();
        
        let valid = MLDSA87::verify(message, &signature, &vk).unwrap();
        
        assert!(valid);
    }

    #[test]
    fn test_ml_dsa_87_reject_wrong_key() {
        let (vk, sk) = MLDSA87::keygen().unwrap();
        let (_, sk2) = MLDSA87::keygen().unwrap();
        
        let message = b"Test message";
        let signature = MLDSA87::sign(message, &sk2).unwrap();
        
        let valid = MLDSA87::verify(message, &signature, &vk).unwrap();
        
        assert!(!valid);
    }

    #[test]
    fn test_hybrid_signature() {
        let (vk65, sk65) = MLDSA65::keygen().unwrap();
        let (vk87, sk87) = MLDSA87::keygen().unwrap();
        
        let message = b"Hybrid signature test";
        let signature = HybridSignature::sign(message, &sk65, &sk87).unwrap();
        
        let valid = HybridSignature::verify(message, &signature, &vk65, &vk87).unwrap();
        
        assert!(valid);
    }
}