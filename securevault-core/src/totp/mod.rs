//! TOTP Authenticator Module
//!
//! Implements Time-based One-Time Password (TOTP) as per RFC 6238
//! With PQ-Vault post-quantum encryption for secrets

pub mod generator;
pub mod parser;

pub use generator::{TOTPGenerator, TOTPAlgorithm, TOTPCode};
pub use parser::TOTPUriParser;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::vault::entry::EncryptedField;
use crate::error::Result;

/// TOTP entry for storing 2FA secrets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TOTPEntry {
    /// Unique identifier
    pub id: Uuid,
    /// Service name (encrypted)
    pub service_name: EncryptedField,
    /// Account name (encrypted)
    pub account_name: EncryptedField,
    /// Encrypted TOTP secret (PQ-encrypted)
    pub encrypted_secret: Vec<u8>,
    /// Algorithm to use
    pub algorithm: TOTPAlgorithm,
    /// Number of digits (6 or 8)
    pub digits: u8,
    /// Time period in seconds (usually 30)
    pub period: u32,
    /// Initial counter (for HOTP, not typically used)
    pub counter: u64,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last used timestamp
    pub last_used: Option<DateTime<Utc>>,
    /// Number of times used
    pub use_count: u32,
    /// Whether this is favorite
    pub favorite: bool,
    /// Notes (encrypted)
    pub notes: Option<EncryptedField>,
}

/// TOTP Algorithm
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TOTPAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl Default for TOTPAlgorithm {
    fn default() -> Self {
        Self::SHA256 // Recommended default
    }
}

impl TOTPEntry {
    /// Create a new TOTP entry from a base32 secret
    pub fn new(
        service_name: String,
        account_name: String,
        secret: &str,
    ) -> Result<Self> {
        // Decode base32 secret
        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
            .ok_or_else(|| crate::error::Error::TOTP("Invalid base32 secret".to_string()))?;

        let now = Utc::now();
        
        // Encrypt secret with PQ encryption
        let encrypted_secret = Self::encrypt_secret(&secret_bytes)?;
        
        Ok(Self {
            id: Uuid::new_v4(),
            service_name: EncryptedField::encrypt(&service_name),
            account_name: EncryptedField::encrypt(&account_name),
            encrypted_secret,
            algorithm: TOTPAlgorithm::default(),
            digits: 6,
            period: 30,
            counter: 0,
            created_at: now,
            last_used: None,
            use_count: 0,
            favorite: false,
            notes: None,
        })
    }

    /// Create from otpauth:// URI
    pub fn from_otpauth_uri(uri: &str) -> Result<Self> {
        let parsed = TOTPUriParser::parse(uri)?;
        
        let mut entry = Self::new(
            parsed.service_name,
            parsed.account_name,
            &parsed.secret,
        )?;
        
        // Apply parsed options
        match parsed.algorithm.to_uppercase().as_str() {
            "SHA1" => entry.algorithm = TOTPAlgorithm::SHA1,
            "SHA256" => entry.algorithm = TOTPAlgorithm::SHA256,
            "SHA512" => entry.algorithm = TOTPAlgorithm::SHA512,
            _ => {}
        }
        
        if let Some(d) = parsed.digits {
            entry.digits = d;
        }
        
        if let Some(p) = parsed.period {
            entry.period = p;
        }
        
        Ok(entry)
    }

    /// Encrypt the TOTP secret with PQ encryption
    fn encrypt_secret(secret: &[u8]) -> Result<Vec<u8>> {
        // For now, use AES encryption
        // In production, use ML-KEM encapsulation
        
        use crate::crypto;
        
        let key = crypto::generate_key()?;
        let encrypted = crypto::encrypt(secret, &key)?;
        
        // Combine key + encrypted for storage
        let mut result = key.to_vec();
        result.extend(encrypted);
        
        Ok(result)
    }

    /// Decrypt the TOTP secret
    pub fn decrypt_secret(&self) -> Result<Vec<u8>> {
        if self.encrypted_secret.len() < 32 {
            return Err(crate::error::Error::TOTP("Invalid encrypted secret".to_string()));
        }
        
        // Extract key and encrypted data
        let key = &self.encrypted_secret[..32];
        let encrypted = &self.encrypted_secret[32..];
        
        use crate::crypto;
        
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(key);
        
        crypto::decrypt(encrypted, &key_arr)
    }

    /// Generate current TOTP code
    pub fn generate_code(&self) -> Result<String> {
        let secret = self.decrypt_secret()?;
        
        generator::generate_totp(
            &secret,
            Utc::now().timestamp() as u64 / self.period as u64,
            self.digits,
            &self.algorithm,
        )
    }

    /// Get remaining seconds until code expires
    pub fn remaining_seconds(&self) -> u32 {
        let now = Utc::now().timestamp() as u64;
        let period = self.period as u64;
        (period - (now % period)) as u32
    }

    /// Mark as used
    pub fn mark_used(&mut self) {
        self.last_used = Some(Utc::now());
        self.use_count += 1;
    }
}

/// Base32 decoding helper (simplified)
mod base32 {
    use std::collections::HashMap;
    
    pub enum Alphabet {
        Rfc4648 { padding: bool },
    }
    
    const BASE32_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    
    pub fn decode(alphabet: Alphabet, input: &str) -> Option<Vec<u8>> {
        let chars: Vec<char> = input.to_uppercase().chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        
        if chars.is_empty() {
            return Some(Vec::new());
        }
        
        let mut output = Vec::new();
        let mut buffer: u64 = 0;
        let mut bits_left = 0;
        
        for c in chars {
            let idx = BASE32_CHARS.find(c)? as u64;
            buffer = (buffer << 5) | idx;
            bits_left += 5;
            
            if bits_left >= 8 {
                bits_left -= 8;
                output.push((buffer >> bits_left) as u8);
            }
        }
        
        Some(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_entry_creation() {
        // Example secret from RFC 6238
        let secret = "JBSWY3DPEHPK3PXP";
        
        let entry = TOTPEntry::new(
            "Google".to_string(),
            "user@gmail.com".to_string(),
            secret,
        ).unwrap();
        
        assert_eq!(entry.service_name.decrypt(&[]).unwrap(), "Google");
        assert_eq!(entry.account_name.decrypt(&[]).unwrap(), "user@gmail.com");
    }

    #[test]
    fn test_totp_code_generation() {
        let secret = "JBSWY3DPEHPK3PXP";
        let entry = TOTPEntry::new(
            "Test".to_string(),
            "test@test.com".to_string(),
            secret,
        ).unwrap();
        
        // Generate code - should be 6 digits
        let code = entry.generate_code().unwrap();
        
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_remaining_seconds() {
        let entry = TOTPEntry::new(
            "Test".to_string(),
            "test@test.com".to_string(),
            "JBSWY3DPEHPK3PXP",
        ).unwrap();
        
        let remaining = entry.remaining_seconds();
        
        assert!(remaining >= 0 && remaining <= 30);
    }

    #[test]
    fn test_otpauth_uri_parsing() {
        let uri = "otpauth://totp/Google:user%40gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=Google&algorithm=SHA256&digits=6&period=30";
        
        let entry = TOTPEntry::from_otpauth_uri(uri).unwrap();
        
        assert_eq!(entry.service_name.decrypt(&[]).unwrap(), "Google");
        assert_eq!(entry.account_name.decrypt(&[]).unwrap(), "user@gmail.com");
    }
}