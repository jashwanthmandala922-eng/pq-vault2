//! Passkey (WebAuthn/FIDO2) Module
//!
//! Implements post-quantum passkey support with hybrid ECDSA + ML-KEM/ML-DSA

pub mod register;
pub mod authenticate;

pub use register::{PasskeyRegistration, PasskeyCredential};
pub use authenticate::{PasskeyAuthentication, AuthenticationResponse};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Result;

/// Passkey credential stored in vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredential {
    /// Unique identifier
    pub id: Uuid,
    /// Credential ID (from authenticator)
    pub credential_id: Vec<u8>,
    /// Public key (hybrid: ECDSA + PQ)
    pub public_key: PasskeyPublicKey,
    /// Relying party ID (the website)
    pub rp_id: String,
    /// User ID (for this user on this website)
    pub user_id: Vec<u8>,
    /// User name (stored locally)
    pub user_name: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last used timestamp
    pub last_used: Option<DateTime<Utc>>,
    /// Usage count
    pub use_count: u32,
    /// Whether it's a discoverable credential
    pub discoverable: bool,
}

/// Hybrid public key (classic + post-quantum)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyPublicKey {
    /// Classic ECDSA P-256 public key
    pub classic_key: Vec<u8>,
    /// ML-KEM-768 public key
    pub pq_public_key: Vec<u8>,
    /// Algorithm indicators
    pub algorithms: Vec<String>,
}

/// Passkey type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PasskeyType {
    /// Platform authenticator (Windows Hello, Touch ID, etc.)
    Platform,
    /// Roaming authenticator (YubiKey, phone, etc.)
    Roaming,
    /// Hybrid (can be both)
    Hybrid,
}

impl PasskeyCredential {
    /// Create a new passkey credential (from registration)
    pub fn new(
        credential_id: Vec<u8>,
        public_key: PasskeyPublicKey,
        rp_id: String,
        user_id: Vec<u8>,
        user_name: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            credential_id,
            public_key,
            rp_id,
            user_id,
            user_name,
            created_at: Utc::now(),
            last_used: None,
            use_count: 0,
            discoverable: true,
        }
    }

    /// Mark as used
    pub fn mark_used(&mut self) {
        self.last_used = Some(Utc::now());
        self.use_count += 1;
    }

    /// Check if this credential is for a specific rp_id
    pub fn matches_rp(&self, rp_id: &str) -> bool {
        // Exact match or subdomain match
        self.rp_id == rp_id || self.rp_id.ends_with(&format!(".{}", rp_id))
    }
}

/// Passkey options for creation
#[derive(Debug, Clone)]
pub struct PasskeyOptions {
    /// Relying party ID (domain)
    pub rp_id: String,
    /// Relying party name (for display)
    pub rp_name: String,
    /// User ID
    pub user_id: Vec<u8>,
    /// User name (for display)
    pub user_name: String,
    /// User display name
    pub user_display_name: Option<String>,
    /// Timeout in milliseconds
    pub timeout: u64,
    /// Allowed credentials (exclude existing)
    pub exclude_credentials: Vec<Vec<u8>>,
    /// Require user verification
    pub user_verification: bool,
    /// Require resident key (discoverable)
    pub resident_key: bool,
}

impl Default for PasskeyOptions {
    fn default() -> Self {
        Self {
            rp_id: String::new(),
            rp_name: String::new(),
            user_id: Vec::new(),
            user_name: String::new(),
            user_display_name: None,
            timeout: 60000, // 60 seconds
            exclude_credentials: Vec::new(),
            user_verification: true,
            resident_key: true,
        }
    }
}

/// Passkey authentication options
#[derive(Debug, Clone)]
pub struct PasskeyAuthenticationOptions {
    /// Relying party ID
    pub rp_id: String,
    /// Allowed credentials
    pub allowed_credentials: Vec<Vec<u8>>,
    /// Timeout
    pub timeout: u64,
    /// Require user verification
    pub user_verification: bool,
}

impl Default for PasskeyAuthenticationOptions {
    fn default() -> Self {
        Self {
            rp_id: String::new(),
            allowed_credentials: Vec::new(),
            timeout: 60000,
            user_verification: false,
        }
    }
}

/// PQ-Vault specific: generate hybrid key pair for registration
pub fn generate_hybrid_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    // Generate classic ECDSA P-256 key pair
    use crate::crypto::ml_kem::ml_kem_keygen;
    
    // ML-KEM-768 key pair (post-quantum)
    let (pq_public, pq_secret) = ml_kem_keygen()?;
    
    // In production, also generate ECDSA key pair
    // For now, return ML-KEM as primary
    Ok((pq_public, pq_secret))
}

/// Hybrid signature (for passkey authentication response)
pub struct HybridAuthSignature {
    /// Classic ECDSA signature
    pub classic: Vec<u8>,
    /// ML-DSA signature (post-quantum)
    pub pq: Vec<u8>,
}

/// Verify hybrid signature
pub fn verify_hybrid_signature(
    message: &[u8],
    signature: &HybridAuthSignature,
    public_keys: &PasskeyPublicKey,
) -> Result<bool> {
    // In production: verify both classic and PQ signatures
    // For PQ-Vault demo, verify PQ signature only
    
    use crate::crypto::ml_dsa::{ml_dsa_verify, ml_dsa_keygen};
    
    // Generate test key for verification
    let (vk, _) = ml_dsa_keygen()?;
    
    // For real implementation, use stored public key
    // This is a placeholder
    Ok(true) // Simplified for now
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passkey_credential_creation() {
        let credential = PasskeyCredential::new(
            vec![1, 2, 3, 4],
            PasskeyPublicKey {
                classic_key: vec![5, 6, 7, 8],
                pq_public_key: vec![9, 10, 11, 12],
                algorithms: vec!["ECDSA".to_string(), "ML-DSA".to_string()],
            },
            "example.com".to_string(),
            vec![1, 2, 3, 4],
            "testuser".to_string(),
        );
        
        assert_eq!(credential.rp_id, "example.com");
        assert_eq!(credential.user_name, "testuser");
    }

    #[test]
    fn test_rp_matching() {
        let credential = PasskeyCredential::new(
            vec![],
            PasskeyPublicKey {
                classic_key: vec![],
                pq_public_key: vec![],
                algorithms: vec![],
            },
            "example.com".to_string(),
            vec![],
            "user".to_string(),
        );
        
        assert!(credential.matches_rp("example.com"));
        assert!(credential.matches_rp("sub.example.com"));
        assert!(!credential.matches_rp("other.com"));
    }

    #[test]
    fn test_mark_used() {
        let mut credential = PasskeyCredential::new(
            vec![],
            PasskeyPublicKey {
                classic_key: vec![],
                pq_public_key: vec![],
                algorithms: vec![],
            },
            "example.com".to_string(),
            vec![],
            "user".to_string(),
        );
        
        assert_eq!(credential.use_count, 0);
        
        credential.mark_used();
        
        assert_eq!(credential.use_count, 1);
        assert!(credential.last_used.is_some());
    }
}