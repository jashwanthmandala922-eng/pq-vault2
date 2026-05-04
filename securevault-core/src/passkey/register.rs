//! Passkey Registration

use crate::error::Result;
use super::{PasskeyCredential, PasskeyPublicKey, PasskeyOptions};

/// Passkey Registration flow
pub struct PasskeyRegistration;

impl PasskeyRegistration {
    /// Generate registration challenge
    pub fn generate_challenge(options: &PasskeyOptions) -> Result<RegistrationChallenge> {
        // In production, generate proper WebAuthn challenge
        // This includes:
        // - challenge: random bytes (min 16)
        // - rp: { id, name }
        // - user: { id, name, displayName }
        // - pubKeyCredParams: algorithm list
        // - timeout, excludeCredentials, etc.
        
        use crate::crypto::rng::random_bytes;
        
        let challenge = random_bytes(32)?;
        
        Ok(RegistrationChallenge {
            challenge,
            rp_id: options.rp_id.clone(),
            rp_name: options.rp_name.clone(),
            user_id: options.user_id.clone(),
            user_name: options.user_name.clone(),
            user_display_name: options.user_display_name.clone(),
            timeout: options.timeout,
            exclude_credentials: options.exclude_credentials.clone(),
            pub_key_cred_params: vec![
                PubKeyCredParam {
                    alg: -7, // ES256
                    type_: "public-key".to_string(),
                },
                // Add PQC algorithms
                PubKeyCredParam {
                    alg: -8, // EdDSA
                    type_: "public-key".to_string(),
                },
            ],
            authenticator_selection: AuthenticatorSelection {
                user_verification: if options.user_verification { 
                    "required".to_string() 
                } else { 
                    "preferred".to_string() 
                },
                resident_key: if options.resident_key { 
                    "required".to_string() 
                } else { 
                    "preferred".to_string() 
                },
            },
        })
    }

    /// Process registration response from authenticator
    pub fn verify_registration(
        challenge: &RegistrationChallenge,
        response: &RegistrationResponse,
    ) -> Result<PasskeyCredential> {
        // 1. Verify client data JSON
        let client_data: ClientDataJSON = serde_json::from_slice(&response.client_data_json)?;
        
        // 2. Verify challenge matches
        if &client_data.challenge != &challenge.challenge {
            return Err(crate::error::Error::Passkey("Challenge mismatch".to_string()));
        }
        
        // 3. Verify origin
        // (In production, validate against rp_id)
        
        // 4. Parse attestation object
        // (Simplified - in production parse CBOR)
        
        // 5. Extract credential ID and public key
        // For now, use response data directly
        
        let credential = PasskeyCredential::new(
            response.credential_id.clone(),
            PasskeyPublicKey {
                classic_key: vec![], // Would extract from attestation
                pq_public_key: vec![], // Would extract from attestation
                algorithms: vec!["ECDSA".to_string(), "ML-DSA".to_string()],
            },
            challenge.rp_id.clone(),
            challenge.user_id.clone(),
            challenge.user_name.clone(),
        );
        
        Ok(credential)
    }
}

/// Registration challenge (sent to authenticator)
#[derive(Debug, Clone)]
pub struct RegistrationChallenge {
    pub challenge: Vec<u8>,
    pub rp_id: String,
    pub rp_name: String,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: Option<String>,
    pub timeout: u64,
    pub exclude_credentials: Vec<Vec<u8>>,
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    pub authenticator_selection: AuthenticatorSelection,
}

/// Public key credential parameter
#[derive(Debug, Clone)]
pub struct PubKeyCredParam {
    pub alg: i32,
    pub type_: String,
}

/// Authenticator selection criteria
#[derive(Debug, Clone)]
pub struct AuthenticatorSelection {
    pub user_verification: String,
    pub resident_key: String,
}

/// Registration response (from authenticator)
#[derive(Debug, Clone)]
pub struct RegistrationResponse {
    pub client_data_json: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub credential_id: Vec<u8>,
}

/// Client data JSON (from client)
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
    fn test_generate_challenge() {
        let options = PasskeyOptions {
            rp_id: "example.com".to_string(),
            rp_name: "Example".to_string(),
            user_id: vec![1, 2, 3, 4],
            user_name: "testuser".to_string(),
            ..Default::default()
        };
        
        let challenge = PasskeyRegistration::generate_challenge(&options).unwrap();
        
        assert!(challenge.challenge.len() >= 16);
        assert_eq!(challenge.rp_id, "example.com");
    }
}