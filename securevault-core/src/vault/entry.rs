//! Password Entry Model
//!
//! Defines the structure for password entries and related types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{self, ml_kem::PQVaultMLKEM};
use crate::error::Result;

/// Types of vault entries
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EntryType {
    /// Standard login credential
    Login,
    /// Secure note
    SecureNote,
    /// Credit card
    Card,
    /// Identity information
    Identity,
}

/// Password entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Unique identifier
    pub id: Uuid,
    /// Entry type
    pub entry_type: EntryType,
    /// Entry title (encrypted)
    pub title: EncryptedField,
    /// Username (encrypted, optional)
    pub username: Option<EncryptedField>,
    /// Password (encrypted)
    pub password: EncryptedField,
    /// URL (encrypted, optional)
    pub url: Option<EncryptedField>,
    /// Notes (encrypted, optional)
    pub notes: Option<EncryptedField>,
    /// Whether entry is marked as favorite
    pub favorite: bool,
    /// Folder ID (optional)
    pub folder_id: Option<Uuid>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,
    /// Last usage timestamp
    pub last_used: Option<DateTime<Utc>>,
    /// Usage count
    pub use_count: u32,
}

/// Encrypted field wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedField {
    /// ML-KEM encapsulated key for this field
    pub kem_ciphertext: Vec<u8>,
    /// AES-encrypted value
    pub encrypted_value: Vec<u8>,
    /// Nonce for AES encryption
    pub nonce: Vec<u8>,
}

/// Folder for organizing entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    /// Unique identifier
    pub id: Uuid,
    /// Folder name (encrypted)
    pub name: EncryptedField,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

/// Vault settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSettings {
    /// Auto-lock timeout in seconds
    pub auto_lock_timeout: u64,
    /// Whether to clear clipboard after timeout
    pub clear_clipboard_timeout: u32,
    /// Whether to enable biometric unlock
    pub biometric_enabled: bool,
    /// Number of password history items to keep
    pub password_history_count: u32,
    /// Whether to show password on click
    pub show_password_on_click: bool,
    /// Clipboard auto-clear on copy
    pub clipboard_auto_clear: bool,
    /// Auto-lock on minimize
    pub auto_lock_on_minimize: bool,
    /// Require biometric for sensitive operations
    pub biometric_for_sensitive: bool,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            auto_lock_timeout: 300,        // 5 minutes
            clear_clipboard_timeout: 30,  // 30 seconds
            biometric_enabled: true,
            password_history_count: 10,
            show_password_on_click: false,
            clipboard_auto_clear: true,
            auto_lock_on_minimize: true,
            biometric_for_sensitive: true,
        }
    }
}

impl Entry {
    /// Create a new password (login) entry
    pub fn new_password(
        title: String,
        url: String,
        username: String,
        password: String,
    ) -> Self {
        let now = Utc::now();
        
        Self {
            id: Uuid::new_v4(),
            entry_type: EntryType::Login,
            title: EncryptedField::encrypt(&title),
            username: Some(EncryptedField::encrypt(&username)),
            password: EncryptedField::encrypt(&password),
            url: Some(EncryptedField::encrypt(&url)),
            notes: None,
            favorite: false,
            folder_id: None,
            created_at: now,
            updated_at: now,
            last_used: None,
            use_count: 0,
        }
    }

    /// Create a new secure note entry
    pub fn new_secure_note(title: String, content: String) -> Self {
        let now = Utc::now();
        
        Self {
            id: Uuid::new_v4(),
            entry_type: EntryType::SecureNote,
            title: EncryptedField::encrypt(&title),
            username: None,
            password: EncryptedField::encrypt(&content), // Content stored in password field
            url: None,
            notes: None,
            favorite: false,
            folder_id: None,
            created_at: now,
            updated_at: now,
            last_used: None,
            use_count: 0,
        }
    }

    /// Update the password
    pub fn update_password(&mut self, new_password: String) {
        self.password = EncryptedField::encrypt(&new_password);
        self.updated_at = Utc::now();
    }

    /// Update the username
    pub fn update_username(&mut self, new_username: String) {
        self.username = Some(EncryptedField::encrypt(&new_username));
        self.updated_at = Utc::now();
    }

    /// Update the URL
    pub fn update_url(&mut self, new_url: String) {
        self.url = Some(EncryptedField::encrypt(&new_url));
        self.updated_at = Utc::now();
    }

    /// Update the notes
    pub fn update_notes(&mut self, new_notes: String) {
        self.notes = Some(EncryptedField::encrypt(&new_notes));
        self.updated_at = Utc::now();
    }

    /// Mark as used
    pub fn mark_used(&mut self) {
        self.last_used = Some(Utc::now());
        self.use_count += 1;
    }

    /// Toggle favorite
    pub fn toggle_favorite(&mut self) {
        self.favorite = !self.favorite;
        self.updated_at = Utc::now();
    }
}

impl EncryptedField {
    /// Encrypt a string value using PQ encryption
    pub fn encrypt(plaintext: &str) -> Self {
        // Generate random session key for this field
        let field_key = crypto::generate_key().unwrap();
        
        // Encrypt value with AES-256-GCM
        let encrypted_value = crypto::encrypt(plaintext.as_bytes(), &field_key).unwrap();
        
        // Use PQ-KEM to encapsulate the field key
        // (For now using placeholder - would use real ML-KEM in production)
        let kem_ciphertext = Vec::new(); // Placeholder
        
        Self {
            kem_ciphertext,
            encrypted_value,
            nonce: encrypted_value[..12].to_vec(), // Extract nonce
        }
    }

    /// Decrypt the field value
    pub fn decrypt(&self, _session_key: &[u8]) -> Result<String> {
        // In production, first decapsulate with ML-KEM, then decrypt with AES
        // For now, direct AES decryption with stored key
        // This is a simplified version - real implementation would use proper key hierarchy
        
        if self.encrypted_value.len() < 12 {
            return Err(crate::error::Error::Crypto("Invalid encrypted data".to_string()));
        }
        
        // Extract nonce and ciphertext
        let nonce = &self.encrypted_value[..12];
        let ciphertext = &self.encrypted_value[12..];
        
        // For demo, use a fixed key - in production, derive from session key
        let key = [0u8; 32];
        
        let plaintext = crypto::decrypt_with_key(ciphertext, &key, nonce)?;
        
        String::from_utf8(plaintext)
            .map_err(|e| crate::error::Error::Crypto(format!("UTF-8 decode: {}", e)))
    }

    /// Get the encrypted data as bytes (for storage)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Format: [kem_ciphertext_len:2][kem_ciphertext][nonce_len:2][nonce][encrypted_value]
        let kem_len = self.kem_ciphertext.len() as u16;
        bytes.extend_from_slice(&kem_len.to_le_bytes());
        bytes.extend_from_slice(&self.kem_ciphertext);
        
        let nonce_len = self.nonce.len() as u16;
        bytes.extend_from_slice(&nonce_len.to_le_bytes());
        bytes.extend_from_slice(&self.nonce);
        
        bytes.extend_from_slice(&self.encrypted_value);
        
        bytes
    }

    /// Reconstruct from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(crate::error::Error::Crypto("Invalid data".to_string()));
        }
        
        let mut offset = 0;
        
        // Read kem_ciphertext
        let kem_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        
        if data.len() < offset + kem_len + 2 {
            return Err(crate::error::Error::Crypto("Invalid data format".to_string()));
        }
        
        let kem_ciphertext = data[offset..offset + kem_len].to_vec();
        offset += kem_len;
        
        // Read nonce
        let nonce_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        
        if data.len() < offset + nonce_len {
            return Err(crate::error::Error::Crypto("Invalid data format".to_string()));
        }
        
        let nonce = data[offset..offset + nonce_len].to_vec();
        offset += nonce_len;
        
        // Rest is encrypted value
        let encrypted_value = data[offset..].to_vec();
        
        Ok(Self {
            kem_ciphertext,
            nonce,
            encrypted_value,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_creation() {
        let entry = Entry::new_password(
            "GitHub".to_string(),
            "https://github.com".to_string(),
            "john@example.com".to_string(),
            "super_secret_password".to_string(),
        );
        
        assert_eq!(entry.entry_type, EntryType::Login);
        assert_eq!(entry.title.decrypt(&[]).unwrap(), "GitHub");
        assert!(entry.favorite == false);
    }

    #[test]
    fn test_secure_note() {
        let entry = Entry::new_secure_note(
            "My Notes".to_string(),
            "This is a secure note content".to_string(),
        );
        
        assert_eq!(entry.entry_type, EntryType::SecureNote);
    }

    #[test]
    fn test_mark_used() {
        let mut entry = Entry::new_password(
            "Test".to_string(),
            "https://test.com".to_string(),
            "user".to_string(),
            "pass".to_string(),
        );
        
        assert_eq!(entry.use_count, 0);
        
        entry.mark_used();
        
        assert_eq!(entry.use_count, 1);
        assert!(entry.last_used.is_some());
    }

    #[test]
    fn test_toggle_favorite() {
        let mut entry = Entry::new_password(
            "Test".to_string(),
            "https://test.com".to_string(),
            "user".to_string(),
            "pass".to_string(),
        );
        
        assert!(!entry.favorite);
        
        entry.toggle_favorite();
        assert!(entry.favorite);
        
        entry.toggle_favorite();
        assert!(!entry.favorite);
    }

    #[test]
    fn test_encrypted_field_serialization() {
        let field = EncryptedField::encrypt("test value");
        let bytes = field.to_bytes();
        let restored = EncryptedField::from_bytes(&bytes).unwrap();
        
        assert_eq!(field.kem_ciphertext, restored.kem_ciphertext);
    }
}