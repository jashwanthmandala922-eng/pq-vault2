//! ML-KEM (Kyber) Post-Quantum Key Encapsulation
//!
//! Implements ML-KEM-768 (NIST security level 1) and ML-KEM-1024 (security level 3)
//! Based on the Kyber KEM from liboqs

use zeroize::Zeroize;
use crate::error::{Error, Result};

/// ML-KEM-768 (Kyber-768) - 128-bit security - RECOMMENDED
pub struct MLKEM768;

impl MLKEM768 {
    /// Create a new ML-KEM-768 instance
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    /// Generate a key pair
    pub fn keygen() -> Result<(Vec<u8>, Vec<u8>)> {
        let kem = liboqs::kems::MLKEM768::new()
            .map_err(|e| Error::Crypto(format!("ML-KEM-768 init: {:?}", e)))?;
        
        let (pk, sk) = kem.generate_keypair()
            .map_err(|e| Error::Crypto(format!("ML-KEM-768 keygen: {:?}", e)))?;
        
        Ok((pk.to_vec(), sk.to_vec()))
    }

    /// Encapsulate - create shared secret for a given public key
    pub fn encaps(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let kem = liboqs::kems::MLKEM768::new()
            .map_err(|e| Error::Crypto(format!("ML-KEM-768 init: {:?}", e)))?;
        
        let pk = liboqs::common::ByteArray::from(public_key);
        let (ct, ss) = kem.encapsulate(&pk)
            .map_err(|e| Error::Crypto(format!("ML-KEM-768 encaps: {:?}", e)))?;
        
        Ok((ct.to_vec(), ss.to_vec()))
    }

    /// Decapsulate - recover shared secret from ciphertext
    pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let kem = liboqs::kems::MLKEM768::new()
            .map_err(|e| Error::Crypto(format!("ML-KEM-768 init: {:?}", e)))?;
        
        let sk = liboqs::common::ByteArray::from(secret_key);
        let ct = liboqs::common::ByteArray::from(ciphertext);
        
        let ss = kem.decapsulate(&sk, &ct)
            .map_err(|e| Error::Crypto(format!("ML-KEM-768 decaps: {:?}", e)))?;
        
        Ok(ss.to_vec())
    }

    /// Get the public key size
    pub fn public_key_size() -> usize {
        1184 // ML-KEM-768 public key
    }

    /// Get the secret key size
    pub fn secret_key_size() -> usize {
        2400 // ML-KEM-768 secret key
    }

    /// Get the ciphertext size
    pub fn ciphertext_size() -> usize {
        1088 // ML-KEM-768 ciphertext
    }

    /// Get the shared secret size
    pub fn shared_secret_size() -> usize {
        32 // 256 bits
    }
}

/// ML-KEM Key Pair
#[derive(Clone)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

/// ML-KEM Encapsulated Key
#[derive(Clone)]
pub struct EncapsulatedKey {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// Convenience functions using ML-KEM-768

/// Generate ML-KEM-768 key pair
pub fn ml_kem_keygen() -> Result<(Vec<u8>, Vec<u8>)> {
    MLKEM768::keygen()
}

/// Encapsulate data for a recipient using their public key
pub fn ml_kem_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    MLKEM768::encaps(public_key)
}

/// Decapsulate using own secret key to recover shared secret
pub fn ml_kem_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    MLKEM768::decapsulate(secret_key, ciphertext)
}

/// PQ-Vault wrapper for encapsulation with additional security
pub struct PQVaultMLKEM;

impl PQVaultMLKEM {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    /// Encrypt a payload using ML-KEM hybrid with AES
    /// 
    /// Returns: ML-KEM ciphertext + nonce (12 bytes) + AES-encrypted payload
    pub fn encrypt(plaintext: &[u8], recipient_public_key: &[u8]) -> Result<Vec<u8>> {
        // ML-KEM encapsulation
        let (kem_ct, shared_secret) = MLKEM768::encaps(recipient_public_key)?;
        
        // Derive AES key from shared secret
        use crate::crypto::kdf::derive_key_hkdf;
        let aes_key = derive_key_hkdf(
            &shared_secret,
            None,
            Some(b"pqvault-aes-encryption"),
            32,
        )?;
        
        // Encrypt payload with AES-256-GCM
        use crate::crypto::aes::encrypt_aes_256_gcm;
        use crate::crypto::rng::random_bytes;
        
        let nonce = random_bytes(12)?;
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&nonce);
        
        let mut aes_key_arr = [0u8; 32];
        aes_key_arr.copy_from_slice(&aes_key);
        
        let encrypted_payload = encrypt_aes_256_gcm(plaintext, &aes_key_arr, &nonce_arr)?;
        
        // Combine: ML-KEM ciphertext + nonce + encrypted payload
        let mut result = kem_ct;
        result.extend(nonce);
        result.extend(encrypted_payload);
        
        Ok(result)
    }

    /// Decrypt a payload using ML-KEM decapsulation + AES
    pub fn decrypt(encrypted_data: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
        // Parse: ML-KEM ciphertext (1088) + nonce (12) + encrypted payload
        if encrypted_data.len() < 1088 + 12 {
            return Err(Error::Crypto("Encrypted data too short".to_string()));
        }
        
        let kem_ciphertext = &encrypted_data[..1088];
        let nonce = &encrypted_data[1088..1088+12];
        let encrypted_payload = &encrypted_data[1088+12..];
        
        // ML-KEM decapsulation to get shared secret
        let shared_secret = MLKEM768::decapsulate(secret_key, kem_ciphertext)?;
        
        // Derive AES key from shared secret
        use crate::crypto::kdf::derive_key_hkdf;
        let aes_key = derive_key_hkdf(
            &shared_secret,
            None,
            Some(b"pqvault-aes-encryption"),
            32,
        )?;
        
        let mut aes_key_arr = [0u8; 32];
        aes_key_arr.copy_from_slice(&aes_key);
        
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce);
        
        // Decrypt payload
        use crate::crypto::aes::decrypt_aes_256_gcm;
        decrypt_aes_256_gcm(encrypted_payload, &aes_key_arr, &nonce_arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires liboqs to be properly linked
    fn test_ml_kem_keygen() {
        let (pk, sk) = ml_kem_keygen().unwrap();
        
        assert_eq!(pk.len(), 1184);
        assert_eq!(sk.len(), 2400);
    }

    #[test]
    #[ignore] // Requires liboqs to be properly linked
    fn test_encaps_decaps() {
        let (pk, sk) = ml_kem_keygen().unwrap();
        
        let (ct, ss) = MLKEM768::encaps(&pk).unwrap();
        
        assert_eq!(ct.len(), 1088);
        assert_eq!(ss.len(), 32);
        
        let ss2 = MLKEM768::decapsulate(&sk, &ct).unwrap();
        
        assert_eq!(ss, ss2);
    }

    #[test]
    #[ignore] // Requires liboqs to be properly linked
    fn test_pq_vault_encrypt_decrypt() {
        let pqkem = PQVaultMLKEM::new().unwrap();
        
        // Generate recipient keypair
        let (pk, sk) = ml_kem_keygen().unwrap();
        
        // Encrypt
        let plaintext = b"Hello, PQ Vault!";
        let encrypted = pqkem.encrypt(plaintext, &pk).unwrap();
        
        // Decrypt
        let decrypted = pqkem.decrypt(&encrypted, &sk).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}

/// ML-KEM-1024 (Kyber-1024) - 192-bit security - MAXIMUM SECURITY
pub struct MLKEM1024;

impl MLKEM1024 {
    /// Create a new ML-KEM-1024 instance
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    /// Generate a key pair (ML-KEM-1024)
    pub fn keygen() -> Result<(Vec<u8>, Vec<u8>)> {
        let kem = liboqs::kems::MLKEM1024::new()
            .map_err(|e| Error::Crypto(format!("ML-KEM-1024 init: {:?}", e)))?;
        
        let (pk, sk) = kem.generate_keypair()
            .map_err(|e| Error::Crypto(format!("ML-KEM-1024 keygen: {:?}", e)))?;
        
        Ok((pk.to_vec(), sk.to_vec()))
    }

    /// Encapsulate - create shared secret for a given public key (ML-KEM-1024)
    pub fn encaps(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let kem = liboqs::kems::MLKEM1024::new()
            .map_err(|e| Error::Crypto(format!("ML-KEM-1024 init: {:?}", e)))?;
        
        let pk = liboqs::common::ByteArray::from(public_key);
        let (ct, ss) = kem.encapsulate(&pk)
            .map_err(|e| Error::Crypto(format!("ML-KEM-1024 encaps: {:?}", e)))?;
        
        Ok((ct.to_vec(), ss.to_vec()))
    }

    /// Decapsulate - recover shared secret from ciphertext (ML-KEM-1024)
    pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let kem = liboqs::kems::MLKEM1024::new()
            .map_err(|e| Error::Crypto(format!("ML-KEM-1024 init: {:?}", e)))?;
        
        let sk = liboqs::common::ByteArray::from(secret_key);
        let ct = liboqs::common::ByteArray::from(ciphertext);
        
        let ss = kem.decapsulate(&sk, &ct)
            .map_err(|e| Error::Crypto(format!("ML-KEM-1024 decaps: {:?}", e)))?;
        
        Ok(ss.to_vec())
    }

    /// Get the public key size
    pub fn public_key_size() -> usize {
        1568 // ML-KEM-1024 public key
    }

    /// Get the secret key size
    pub fn secret_key_size() -> usize {
        3168 // ML-KEM-1024 secret key
    }

    /// Get the ciphertext size
    pub fn ciphertext_size() -> usize {
        1568 // ML-KEM-1024 ciphertext
    }

    /// Get the shared secret size
    pub fn shared_secret_size() -> usize {
        32 // 256 bits
    }
}

/// Generate ML-KEM-1024 key pair (maximum security)
pub fn ml_kem_1024_keygen() -> Result<(Vec<u8>, Vec<u8>)> {
    MLKEM1024::keygen()
}

/// Encapsulate data for a recipient using ML-KEM-1024
pub fn ml_kem_1024_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    MLKEM1024::encaps(public_key)
}

/// Decapsulate using ML-KEM-1024
pub fn ml_kem_1024_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    MLKEM1024::decapsulate(secret_key, ciphertext)
}

/// PQ-Vault wrapper for ML-KEM-1024 (maximum security)
pub struct PQVaultMLKEM1024;

impl PQVaultMLKEM1024 {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    /// Encrypt a payload using ML-KEM-1024 hybrid with AES
    /// 
    /// Returns: ML-KEM-1024 ciphertext + nonce (12 bytes) + AES-encrypted payload
    pub fn encrypt(plaintext: &[u8], recipient_public_key: &[u8]) -> Result<Vec<u8>> {
        let (kem_ct, shared_secret) = MLKEM1024::encaps(recipient_public_key)?;
        
        use crate::crypto::kdf::derive_key_hkdf;
        let aes_key = derive_key_hkdf(
            &shared_secret,
            None,
            Some(b"pqvault-aes-1024-encryption"),
            32,
        )?;
        
        use crate::crypto::aes::encrypt_aes_256_gcm;
        use crate::crypto::rng::random_bytes;
        
        let nonce = random_bytes(12)?;
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&nonce);
        
        let mut aes_key_arr = [0u8; 32];
        aes_key_arr.copy_from_slice(&aes_key);
        
        let encrypted_payload = encrypt_aes_256_gcm(plaintext, &aes_key_arr, &nonce_arr)?;
        
        let mut result = kem_ct;
        result.extend(nonce);
        result.extend(encrypted_payload);
        
        Ok(result)
    }

    /// Decrypt a payload using ML-KEM-1024 decapsulation + AES
    pub fn decrypt(encrypted_data: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
        let kem_ct_size = MLKEM1024::ciphertext_size();
        
        if encrypted_data.len() < kem_ct_size + 12 {
            return Err(Error::Crypto("Invalid encrypted data size".to_string()));
        }
        
        let kem_ct = &encrypted_data[..kem_ct_size];
        let nonce = &encrypted_data[kem_ct_size..kem_ct_size + 12];
        let encrypted_payload = &encrypted_data[kem_ct_size + 12..];
        
        let shared_secret = MLKEM1024::decapsulate(secret_key, kem_ct)?;
        
        use crate::crypto::kdf::derive_key_hkdf;
        let aes_key = derive_key_hkdf(
            &shared_secret,
            None,
            Some(b"pqvault-aes-1024-encryption"),
            32,
        )?;
        
        use crate::crypto::aes::decrypt_aes_256_gcm;
        
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce);
        
        let mut aes_key_arr = [0u8; 32];
        aes_key_arr.copy_from_slice(&aes_key);
        
        decrypt_aes_256_gcm(encrypted_payload, &aes_key_arr, &nonce_arr)
    }
}

#[cfg(test)]
mod tests_ml_kem_1024 {
    use super::*;

    #[test]
    fn test_ml_kem_1024_keygen() {
        let (pk, sk) = MLKEM1024::keygen().unwrap();
        
        assert_eq!(pk.len(), MLKEM1024::public_key_size());
        assert_eq!(sk.len(), MLKEM1024::secret_key_size());
    }

    #[test]
    fn test_ml_kem_1024_encaps_decaps() {
        let (pk, sk) = MLKEM1024::keygen().unwrap();
        
        let (ct, ss1) = MLKEM1024::encaps(&pk).unwrap();
        let ss2 = MLKEM1024::decapsulate(&sk, &ct).unwrap();
        
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_ml_kem_1024_hybrid_encrypt() {
        let (pk, sk) = MLKEM1024::keygen().unwrap();
        
        let pqkem = PQVaultMLKEM1024::new().unwrap();
        
        let plaintext = b"Maximum Security PQ Vault!";
        let encrypted = pqkem.encrypt(plaintext, &pk).unwrap();
        
        let decrypted = pqkem.decrypt(&encrypted, &sk).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}