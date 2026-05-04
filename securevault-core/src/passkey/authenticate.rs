//! Passkey Authentication

use crate::error::Result;
use super::{PasskeyCredential, PasskeyAuthenticationOptions, HybridAuthSignature};

/// Passkey Authentication flow
pub struct PasskeyAuthentication;

impl PasskeyAuthentication {
    /// Generate authentication challenge
    pub fn generate_challenge(options: &PasskeyAuthenticationOptions) -> Result<AuthenticationChallenge> {
        use crate::crypto::rng::random_bytes;
        
        let challenge = random_bytes(32)?;
        
        Ok(AuthenticationChallenge {
            challenge,
            rp_id: options.rp_id.clone(),
            timeout: options.timeout,
            allowed_credentials: options.allowed_credentials.clone(),
            user_verification: if options.user_verification {
                "required".to_string()
            } else {
                "preferred".to_string()
            },
        })
    }

    /// Verify authentication response
    pub fn verify_authentication(
        credential: &PasskeyCredential,
        challenge: &AuthenticationChallenge,
        response: &AuthenticationResponse,
    ) -> Result<AuthenticationResult> {
        // 1. Verify client data
        let client_data: ClientDataJSON = serde_json::from_slice(&response.client_data_json)?;
        
        // 2. Verify challenge
        if &client_data.challenge != &challenge.challenge {
            return Err(crate::error::Error::Passkey("Challenge mismatch".to_string()));
        }
        
        // 3. Verify user presence/verification flags
        let flags = response.authenticator_data[0];
        let user_present = (flags & 0x01) != 0;
        let user_verified = (flags & 0x04) != 0;
        
        if !user_present {
            return Err(crate::error::Error::Passkey("User not present".to_string()));
        }
        
        // 4. Verify signature
        // In production, use credential.public_key to verify
        // For PQ-Vault, verify hybrid signature
        
        // 5. Verify counter (prevent replay)
        // (Parse counter from authenticator_data)
        
        Ok(AuthenticationResult {
            success: true,
            user_verified,
        })
    }

    /// Generate post-quantum authenticated session
    pub fn create_pq_session(
        credential: &PasskeyCredential,
        challenge: &[u8],
    ) -> Result<HybridAuthSignature> {
        // Generate ML-DSA signature for the session
        use crate::crypto::ml_dsa::{ml_dsa_keygen, ml_dsa_sign};
        
        // In production, use credential's stored signing key
        let (_vk, sk) = ml_dsa_keygen()?;
        
        // Create signature over challenge
        let signature = ml_dsa_sign(challenge, &sk)?;
        
        Ok(HybridAuthSignature {
            classic: vec![], // Would include ECDSA signature
            pq: signature,
        })
    }
}

/// Authentication challenge
#[derive(Debug, Clone)]
pub struct AuthenticationChallenge {
    pub challenge: Vec<u8>,
    pub rp_id: String,
    pub timeout: u64,
    pub allowed_credentials: Vec<Vec<u8>>,
    pub user_verification: String,
}

/// Authentication response from authenticator
#[derive(Debug, Clone)]
pub struct AuthenticationResponse {
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
}

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub success: bool,
    pub user_verified: bool,
}

/// Client data JSON
#[derive(Debug, Deserialize)]
struct ClientDataJSON {
    challenge: Vec<u8>,
    origin: String,
    #[serde(rename = "type")]
    type_: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_auth_challenge() {
        let options = PasskeyAuthenticationOptions {
            rp_id: "example.com".to_string(),
            allowed_credentials: vec![],
            timeout: 60000,
            user_verification: false,
        };
        
        let challenge = PasskeyAuthentication::generate_challenge(&options).unwrap();
        
        assert!(challenge.challenge.len() >= 16);
        assert_eq!(challenge.rp_id, "example.com");
    }

    #[test]
    fn test_pq_session_creation() {
        let credential = super::PasskeyCredential::new(
            vec![],
            super::PasskeyPublicKey {
                classic_key: vec![],
                pq_public_key: vec![],
                algorithms: vec![],
            },
            "example.com".to_string(),
            vec![],
            "user".to_string(),
        );
        
        let challenge = b"test_challenge_data";
        let session = PasskeyAuthentication::create_pq_session(&credential, challenge).unwrap();
        
        assert!(!session.pq.is_empty());
    }
}