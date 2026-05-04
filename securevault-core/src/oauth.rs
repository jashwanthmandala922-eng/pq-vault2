//! OAuth Module
//!
//! Handles OAuth 2.0 authentication and key derivation for PQ-Vault
//! Supports Google and Apple OAuth providers

use serde::{Deserialize, Serialize};
use crate::error::{Result};

/// OAuth provider
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OAuthProvider {
    Google,
    Apple,
    GitHub,
    Facebook,
}

/// OAuth tokens
#[derive(Debug, Clone)]
pub struct OAuthTokens {
    /// Access token
    pub access_token: String,
    /// Refresh token (if available)
    pub refresh_token: Option<String>,
    /// Token type (usually "Bearer")
    pub token_type: String,
    /// Expiration timestamp
    pub expires_at: u64,
    /// User info from provider
    pub user_info: OAuthUserInfo,
}

/// OAuth user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    /// Unique user ID
    pub id: String,
    /// Email address
    pub email: String,
    /// Display name
    pub name: Option<String>,
    /// Profile picture URL
    pub picture: Option<String>,
}

/// OAuth configuration
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// OAuth provider
    pub provider: OAuthProvider,
    /// Client ID
    pub client_id: String,
    /// Redirect URI
    pub redirect_uri: String,
    /// Scopes to request
    pub scopes: Vec<String>,
}

impl OAuthConfig {
    /// Create Google OAuth config
    pub fn google(client_id: &str, redirect_uri: &str) -> Self {
        Self {
            provider: OAuthProvider::Google,
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
        }
    }

    /// Create Apple OAuth config
    pub fn apple(client_id: &str, redirect_uri: &str) -> Self {
        Self {
            provider: OAuthProvider::Apple,
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scopes: vec![
                "name".to_string(),
                "email".to_string(),
            ],
        }
    }

    /// Generate authorization URL
    pub fn authorization_url(&self, state: &str) -> String {
        let base_url = match self.provider {
            OAuthProvider::Google => "https://accounts.google.com/o/oauth2/v2/auth",
            OAuthProvider::Apple => "https://appleid.apple.com/auth/authorize",
            OAuthProvider::GitHub => "https://github.com/login/oauth/authorize",
            OAuthProvider::Facebook => "https://www.facebook.com/v12.0/dialog/oauth",
        };

        let scope_str = self.scopes.join(" ");

        format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
            base_url,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.redirect_uri),
            urlencoding::encode(&scope_str),
            urlencoding::encode(state)
        )
    }
}

/// Exchange code for tokens (would be called from client with real response)
pub fn exchange_code_for_tokens(
    _config: &OAuthConfig,
    _code: &str,
) -> Result<OAuthTokens> {
    // In production, this would make HTTP request to token endpoint
    // For now, return placeholder that would be replaced by actual token from OAuth provider
    
    // This is a mock - real implementation would call:
    // POST https://oauth2.googleapis.com/token
    // or POST https://appleid.apple.com/auth/token
    
    Err(crate::error::Error::OAuth(
        "OAuth token exchange must be performed client-side".to_string()
    ))
}

/// Create OAuth tokens from successful authentication
pub fn create_tokens(
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
    user_info: OAuthUserInfo,
) -> OAuthTokens {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    OAuthTokens {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_at: now + expires_in,
        user_info,
    }
}

/// Derive encryption key from OAuth tokens
pub fn derive_key_from_oauth(tokens: &OAuthTokens) -> Result<Vec<u8>> {
    // Use HKDF to derive encryption key from OAuth access token
    use crate::crypto::kdf::derive_key_hkdf;
    
    // Derive a 256-bit key from the OAuth token
    let key = derive_key_hkdf(
        tokens.access_token.as_bytes(),
        None,
        Some(b"pq-vault-oauth-key-derivation"),
        32,
    )?;
    
    Ok(key)
}

/// Derive master key for vault (combines OAuth key with device-specific salt)
pub fn derive_vault_key(oauth_key: &[u8], device_salt: &[u8]) -> Result<Vec<u8>> {
    use crate::crypto::kdf::derive_key_hkdf;
    
    // Combine OAuth key with device salt for device-specific vault
    let mut input = Vec::new();
    input.extend(oauth_key);
    input.extend(device_salt);
    
    let vault_key = derive_key_hkdf(
        &input,
        None,
        Some(b"pq-vault-master"),
        32,
    )?;
    
    Ok(vault_key)
}

/// Verify OAuth tokens are still valid
pub fn verify_tokens(tokens: &OAuthTokens) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    tokens.expires_at > now
}

/// Refresh OAuth tokens
pub fn refresh_tokens(
    _config: &OAuthConfig,
    _refresh_token: &str,
) -> Result<OAuthTokens> {
    // In production, would call token refresh endpoint
    Err(crate::error::Error::OAuth(
        "OAuth refresh must be performed client-side".to_string()
    ))
}

/// URL encoding helper
mod urlencoding {
    pub fn encode(input: &str) -> String {
        let mut encoded = String::new();
        for byte in input.as_bytes() {
            match *byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(*byte as char);
                }
                _ => {
                    encoded.push_str(&format!("%{:02X}", byte));
                }
            }
        }
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_config() {
        let config = OAuthConfig::google("client-id", "redirect://callback");
        
        assert_eq!(config.provider, OAuthProvider::Google);
        assert_eq!(config.scopes.len(), 3);
    }

    #[test]
    fn test_apple_config() {
        let config = OAuthConfig::apple("client-id", "redirect://callback");
        
        assert_eq!(config.provider, OAuthProvider::Apple);
    }

    #[test]
    fn test_authorization_url() {
        let config = OAuthConfig::google("test-client", "https://example.com/callback");
        
        let url = config.authorization_url("random-state");
        
        assert!(url.contains("accounts.google.com"));
        assert!(url.contains("test-client"));
    }

    #[test]
    fn test_derive_key() {
        let tokens = create_tokens(
            "mock-access-token".to_string(),
            None,
            3600,
            OAuthUserInfo {
                id: "user123".to_string(),
                email: "test@example.com".to_string(),
                name: Some("Test User".to_string()),
                picture: None,
            },
        );
        
        let key = derive_key_from_oauth(&tokens).unwrap();
        
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_verify_tokens() {
        let tokens = create_tokens(
            "access".to_string(),
            None,
            3600,
            OAuthUserInfo {
                id: "1".to_string(),
                email: "test@test.com".to_string(),
                name: None,
                picture: None,
            },
        );
        
        assert!(verify_tokens(&tokens));
    }

    #[test]
    fn test_url_encoding() {
        assert_eq!(urlencoding::encode("hello world"), "hello%20world");
        assert_eq!(urlencoding::encode("a@b.com"), "a%40b.com");
    }
}