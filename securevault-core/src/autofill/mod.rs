//! Autofiller Module
//!
//! Implements password autofill with PQ-Vault encryption

pub mod matcher;

pub use matcher::URLMatcher;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::sha3;
use crate::vault::entry::EncryptedField;
use crate::error::Result;

/// Autofill credential stored for websites
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutofillCredential {
    /// Unique ID
    pub id: Uuid,
    /// URL hash (SHA3-256 for matching)
    pub url_hash: [u8; 32],
    /// URL (encrypted, for display)
    pub encrypted_url: EncryptedField,
    /// Username (encrypted)
    pub encrypted_username: EncryptedField,
    /// Password (encrypted)
    pub encrypted_password: EncryptedField,
    /// Domain (for fuzzy matching)
    pub domain: String,
    /// Subdomain level (for matching subdomains)
    pub subdomain_depth: u8,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last used timestamp
    pub last_used: Option<DateTime<Utc>>,
    /// Usage count
    pub use_count: u32,
    /// Entry ID reference (if linked to vault entry)
    pub entry_id: Option<Uuid>,
}

impl AutofillCredential {
    /// Create new autofill credential from a vault entry
    pub fn from_entry(
        url: &str,
        username: &str,
        password: &str,
        entry_id: Option<Uuid>,
    ) -> Result<Self> {
        // Hash URL for secure matching
        let url_hash = sha3::hash_url(url);
        
        // Extract domain
        let domain = extract_domain(url)?;
        
        // Calculate subdomain depth
        let subdomain_depth = count_subdomain_depth(&domain);
        
        Ok(Self {
            id: Uuid::new_v4(),
            url_hash,
            encrypted_url: EncryptedField::encrypt(url),
            encrypted_username: EncryptedField::encrypt(username),
            encrypted_password: EncryptedField::encrypt(password),
            domain,
            subdomain_depth,
            created_at: Utc::now(),
            last_used: None,
            use_count: 0,
            entry_id,
        })
    }

    /// Check if this credential matches a URL
    pub fn matches_url(&self, url: &str) -> bool {
        let target_hash = sha3::hash_url(url);
        
        // Exact match
        if target_hash == self.url_hash {
            return true;
        }
        
        // Fuzzy domain match
        if let Ok(target_domain) = extract_domain(url) {
            return self.matches_domain(&target_domain);
        }
        
        false
    }

    /// Check if matches a domain
    pub fn matches_domain(&self, domain: &str) -> bool {
        // Same domain
        if self.domain == domain {
            return true;
        }
        
        // Subdomain: example.com matches sub.example.com
        if domain.ends_with(&format!(".{}", self.domain)) {
            return true;
        }
        
        false
    }

    /// Decrypt username (requires session key)
    pub fn get_username(&self, _session_key: &[u8]) -> Result<String> {
        // In production, decrypt with session key
        // For demo, use stored encryption
        self.encrypted_username.decrypt(_session_key)
    }

    /// Decrypt password (requires session key)
    pub fn get_password(&self, _session_key: &[u8]) -> Result<String> {
        self.encrypted_password.decrypt(_session_key)
    }

    /// Mark as used
    pub fn mark_used(&mut self) {
        self.last_used = Some(Utc::now());
        self.use_count += 1;
    }

    /// Update credentials
    pub fn update(&mut self, username: &str, password: &str) -> Result<()> {
        self.encrypted_username = EncryptedField::encrypt(username);
        self.encrypted_password = EncryptedField::encrypt(password);
        Ok(())
    }
}

/// Extract domain from URL
fn extract_domain(url: &str) -> Result<String> {
    use url::Url;
    
    let parsed = Url::parse(url)
        .map_err(|e| crate::error::Error::Autofill(format!("Invalid URL: {}", e)))?;
    
    let host = parsed.host_str()
        .ok_or_else(|| crate::error::Error::Autofill("No host in URL".to_string()))?;
    
    // Remove www prefix
    let domain = if host.starts_with("www.") {
        &host[4..]
    } else {
        host
    };
    
    Ok(domain.to_string())
}

/// Count subdomain depth
fn count_subdomain_depth(domain: &str) -> u8 {
    domain.split('.').count() as u8 - 1
}

/// Autofill match result
#[derive(Debug, Clone)]
pub struct AutofillMatch {
    pub credential: AutofillCredential,
    pub match_type: MatchType,
    pub confidence: f32,
}

/// Type of match
#[derive(Debug, Clone, PartialEq)]
pub enum MatchType {
    /// Exact URL match
    Exact,
    /// Domain match
    Domain,
    /// Subdomain match
    Subdomain,
}

impl AutofillCredential {
    /// Find best matching credential for a URL
    pub fn find_best_match(url: &str, credentials: &[AutofillCredential]) -> Option<AutofillMatch> {
        let mut best_match: Option<AutofillMatch> = None;
        
        for cred in credentials {
            if cred.matches_url(url) {
                let (match_type, confidence) = if cred.url_hash == sha3::hash_url(url) {
                    (MatchType::Exact, 1.0)
                } else {
                    let target_domain = extract_domain(url).unwrap_or_default();
                    if cred.domain == target_domain {
                        (MatchType::Domain, 0.9)
                    } else if cred.matches_domain(&target_domain) {
                        (MatchType::Subdomain, 0.7)
                    } else {
                        continue;
                    }
                };
                
                // Update if better match
                if best_match.is_none() || confidence > best_match.as_ref().unwrap().confidence {
                    best_match = Some(AutofillMatch {
                        credential: cred.clone(),
                        match_type,
                        confidence,
                    });
                }
            }
        }
        
        best_match
    }
}

/// Autofill settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutofillSettings {
    /// Enable autofill
    pub enabled: bool,
    /// Auto-fill on page load
    pub auto_fill: bool,
    /// Show notification on page load
    pub show_notification: bool,
    /// Clear clipboard after copy
    pub clear_clipboard: bool,
    /// Clipboard clear timeout (seconds)
    pub clipboard_timeout: u32,
    /// Require biometric before fill
    pub require_biometric: bool,
    /// Lock after inactivity (seconds)
    pub lock_timeout: u64,
}

impl Default for AutofillSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_fill: false,
            show_notification: true,
            clear_clipboard: true,
            clipboard_timeout: 30,
            require_biometric: true,
            lock_timeout: 300,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_creation() {
        let cred = AutofillCredential::from_entry(
            "https://github.com/login",
            "user@example.com",
            "password123",
            None,
        ).unwrap();
        
        assert_eq!(cred.domain, "github.com");
        assert_eq!(cred.subdomain_depth, 0);
    }

    #[test]
    fn test_url_matching() {
        let cred = AutofillCredential::from_entry(
            "https://github.com/login",
            "user",
            "pass",
            None,
        ).unwrap();
        
        assert!(cred.matches_url("https://github.com/login"));
        assert!(cred.matches_url("https://github.com"));
        assert!(cred.matches_url("https://api.github.com"));
        assert!(!cred.matches_url("https://gitlab.com"));
    }

    #[test]
    fn test_domain_matching() {
        let cred = AutofillCredential::from_entry(
            "https://example.com/login",
            "user",
            "pass",
            None,
        ).unwrap();
        
        assert!(cred.matches_domain("example.com"));
        assert!(cred.matches_domain("sub.example.com"));
        assert!(cred.matches_domain("deep.sub.example.com"));
        assert!(!cred.matches_domain("notexample.com"));
    }

    #[test]
    fn test_best_match() {
        let creds = vec![
            AutofillCredential::from_entry("https://github.com", "user1", "pass1", None).unwrap(),
            AutofillCredential::from_entry("https://github.com/login", "user2", "pass2", None).unwrap(),
        ];
        
        let match_result = AutofillCredential::find_best_match("https://github.com/login", &creds);
        
        assert!(match_result.is_some());
        assert_eq!(match_result.unwrap().match_type, MatchType::Exact);
    }
}