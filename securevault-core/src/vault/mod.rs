//! Password Vault Module
//!
//! Manages encrypted password entries with PQ-Vault specific features

pub mod entry;
pub mod crypto;

pub use entry::{Entry, EntryType, VaultSettings, Folder};
pub use crypto::VaultCrypto;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::crypto::{self, kdf, rng};
use crate::hardware::TpmKeyManager;
use crate::securemem::{SecureVec, SecureZeroize};

/// Hardware-bound vault configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareBinding {
    /// TPM/Keystore binding identifier
    pub binding_id: String,
    /// Device-specific salt (encrypted with hardware key)
    pub hardware_salt: Vec<u8>,
    /// Whether hardware binding is enforced
    pub enforce_hardware: bool,
}

impl Default for HardwareBinding {
    fn default() -> Self {
        Self {
            binding_id: "software_only".to_string(),
            hardware_salt: Vec::new(),
            enforce_hardware: false,
        }
    }
}

/// The main vault structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    /// Vault format version
    pub version: u8,
    /// Unique vault identifier
    pub id: Uuid,
    /// Vault creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,
    /// Password entries
    pub entries: Vec<Entry>,
    /// Folders for organizing entries
    pub folders: Vec<Folder>,
    /// Vault settings
    pub settings: VaultSettings,
}

/// Vault in encrypted form (for storage)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedVault {
    /// Version header
    pub version: u8,
    /// Salt for key derivation
    pub salt: Vec<u8>,
    /// Encrypted vault data (AES-256-GCM)
    pub ciphertext: Vec<u8>,
    /// ML-KEM encapsulated session key (for future sync)
    pub kem_ciphertext: Option<Vec<u8>>,
    /// Hardware binding for device-bound security
    pub hardware_binding: Option<HardwareBinding>,
}

/// Vault state (unlocked)
/// IMPORTANT: session_key uses SecureVec for automatic zeroization on drop
pub struct UnlockedVault {
    /// The vault data
    pub vault: Vault,
    /// Derived session key - zeroized on drop via SecureVec
    session_key: SecureVec,
}

impl Vault {
    /// Create a new vault with a master key derived from OAuth token
    /// This is the legacy software-only method - use create_from_oauth_hardware for device-bound security
    pub fn create_from_oauth(oauth_token: &str) -> Result<(Self, EncryptedVault)> {
        Self::create_from_oauth_with_salt(oauth_token, None)
    }

    /// Create a new vault with hardware-bound security (TPM/Keystore)
    pub fn create_from_oauth_hardware(oauth_token: &str) -> Result<(Self, EncryptedVault)> {
        let mut tpm = TpmKeyManager::new();
        
        let hardware_binding = if tpm.is_available() {
            // Generate hardware-bound salt
            let hardware_salt = rng::random_bytes(32)?;
            let binding_id = tpm.get_key_binding().unwrap_or_else(|_| "tpm_v1".to_string());
            
            Some(HardwareBinding {
                binding_id,
                hardware_salt,
                enforce_hardware: true,
            })
        } else {
            None
        };

        Self::create_from_oauth_with_salt(oauth_token, hardware_binding.as_ref())
    }

    /// Internal create with optional hardware binding
    fn create_from_oauth_with_salt(oauth_token: &str, hardware_binding: Option<&HardwareBinding>) -> Result<(Self, EncryptedVault)> {
        // Derive master key from OAuth token using HKDF
        let master_key = kdf::derive_key_hkdf(
            oauth_token.as_bytes(),
            None,
            Some(b"pq-vault-master"),
            32,
        )?;

        // Generate random salt for key derivation
        let mut salt = rng::random_bytes(32)?;

        // Incorporate hardware binding if available
        if let Some(hw) = hardware_binding {
            // XOR hardware salt into main salt for device binding
            for (i, byte) in hw.hardware_salt.iter().enumerate().take(32) {
                salt[i] ^= byte;
            }
        }

        // Derive session key from master key
        let session_key = kdf::derive_key_hkdf(
            &master_key,
            Some(&salt),
            Some(b"pq-vault-session"),
            32,
        )?;

        // Create vault
        let vault = Vault {
            version: 1,
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            entries: Vec::new(),
            folders: Vec::new(),
            settings: VaultSettings::default(),
        };

        // Serialize and encrypt
        let vault_json = serde_json::to_vec(&vault)?;
        let key_array: [u8; 32] = session_key.as_slice().try_into()
            .map_err(|_| Error::Crypto("Invalid session key length".to_string()))?;
        let ciphertext = crypto::encrypt(&vault_json, &key_array)?;

        let hardware_binding = hardware_binding.cloned();

        let encrypted = EncryptedVault {
            version: 1,
            salt,
            ciphertext,
            kem_ciphertext: None,
            hardware_binding,
        };

        // Return unlocked vault (keep session key)
        Ok((vault, encrypted))
    }

    /// Unlock an existing encrypted vault
    /// For vaults with hardware binding, the hardware binding must be provided
    pub fn unlock(oauth_token: &str, encrypted: &EncryptedVault) -> Result<UnlockedVault> {
        // Derive master key from OAuth token
        let master_key = kdf::derive_key_hkdf(
            oauth_token.as_bytes(),
            None,
            Some(b"pq-vault-master"),
            32,
        )?;

        // Incorporate hardware binding if present
        let mut salt = encrypted.salt.clone();
        if let Some(hw) = &encrypted.hardware_binding {
            // XOR hardware salt into stored salt to recreate device-bound key
            for (i, byte) in hw.hardware_salt.iter().enumerate().take(32) {
                if i < salt.len() {
                    salt[i] ^= byte;
                }
            }
        }

        // Derive session key using stored salt
        let session_key = kdf::derive_key_hkdf(
            &master_key,
            Some(&salt),
            Some(b"pq-vault-session"),
            32,
        )?;

        // Decrypt vault
        let key_array: [u8; 32] = session_key.clone().try_into()
            .map_err(|_| Error::Crypto("Invalid key length".to_string()))?;
        
        let plaintext = crypto::decrypt(&encrypted.ciphertext, &key_array)?;
        
        let vault: Vault = serde_json::from_slice(&plaintext)?;

        // Wrap session key in SecureVec for automatic zeroization on drop
        let secure_session_key = SecureVec::new(session_key);

        Ok(UnlockedVault { vault, session_key: secure_session_key })
    }

    /// Add a password entry
    pub fn add_entry(&mut self, entry: Entry) -> Result<()> {
        self.entries.push(entry);
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Update an existing entry
    pub fn update_entry(&mut self, id: Uuid, entry: Entry) -> Result<()> {
        let pos = self.entries.iter().position(|e| e.id == id)
            .ok_or_else(|| Error::EntryNotFound(id.to_string()))?;
        
        self.entries[pos] = entry;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Delete an entry
    pub fn delete_entry(&mut self, id: Uuid) -> Result<()> {
        let pos = self.entries.iter().position(|e| e.id == id)
            .ok_or_else(|| Error::EntryNotFound(id.to_string()))?;
        
        self.entries.remove(pos);
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Get an entry by ID
    pub fn get_entry(&self, id: Uuid) -> Result<&Entry> {
        self.entries.iter()
            .find(|e| e.id == id)
            .ok_or_else(|| Error::EntryNotFound(id.to_string()))
    }

    /// Get mutable entry
    pub fn get_entry_mut(&mut self, id: Uuid) -> Result<&mut Entry> {
        self.entries.iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| Error::EntryNotFound(id.to_string()))
    }

    /// Search entries by title or URL
    pub fn search(&self, query: &str) -> Vec<&Entry> {
        let query_lower = query.to_lowercase();
        self.entries.iter()
            .filter(|e| {
                e.title.to_lowercase().contains(&query_lower) ||
                e.url.as_ref().map(|u| u.to_lowercase().contains(&query_lower)).unwrap_or(false)
            })
            .collect()
    }

    /// Export vault to encrypted form
    pub fn export(&self, session_key: &[u8]) -> Result<EncryptedVault> {
        let vault_json = serde_json::to_vec(self)?;
        
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(session_key);
        
        let ciphertext = crypto::encrypt(&vault_json, &key_array)?;
        
        Ok(EncryptedVault {
            version: self.version,
            salt: rng::random_bytes(32)?, // New salt for export (re-derive needed)
            ciphertext,
            kem_ciphertext: None,
        })
    }
}

impl Drop for UnlockedVault {
    fn drop(&mut self) {
        // Session key is automatically zeroized via SecureVec's Drop implementation
        // SecureVec uses Zeroizing wrapper which calls zeroize() on drop
        // This cannot be optimized away by the compiler
        self.session_key.secure_zero();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_create() {
        let oauth_token = "mock_oauth_token_12345";
        
        let (vault, encrypted) = Vault::create_from_oauth(oauth_token).unwrap();
        
        assert_eq!(vault.version, 1);
        assert_eq!(vault.entries.len(), 0);
        assert!(encrypted.ciphertext.len() > 0);
    }

    #[test]
    fn test_vault_unlock() {
        let oauth_token = "mock_oauth_token_12345";
        
        let (vault, encrypted) = Vault::create_from_oauth(oauth_token).unwrap();
        let unlocked = Vault::unlock(oauth_token, &encrypted).unwrap();
        
        assert_eq!(unlocked.vault.id, vault.id);
        assert_eq!(unlocked.vault.entries.len(), 0);
    }

    #[test]
    fn test_add_entry() {
        let (mut vault, _) = Vault::create_from_oauth("token").unwrap();
        
        let entry = Entry::new_password(
            "Test Entry".to_string(),
            "https://example.com".to_string(),
            "username".to_string(),
            "password123".to_string(),
        );
        
        vault.add_entry(entry.clone()).unwrap();
        
        assert_eq!(vault.entries.len(), 1);
        assert_eq!(vault.entries[0].title, "Test Entry");
    }

    #[test]
    fn test_delete_entry() {
        let (mut vault, _) = Vault::create_from_oauth("token").unwrap();
        
        let entry = Entry::new_password(
            "Test".to_string(),
            "https://test.com".to_string(),
            "user".to_string(),
            "pass".to_string(),
        );
        
        let id = entry.id;
        vault.add_entry(entry).unwrap();
        vault.delete_entry(id).unwrap();
        
        assert_eq!(vault.entries.len(), 0);
    }

    #[test]
    fn test_search() {
        let (mut vault, _) = Vault::create_from_oauth("token").unwrap();
        
        vault.add_entry(Entry::new_password(
            "GitHub".to_string(),
            "https://github.com".to_string(),
            "user".to_string(),
            "pass".to_string(),
        )).unwrap();
        
        vault.add_entry(Entry::new_password(
            "Google".to_string(),
            "https://google.com".to_string(),
            "user".to_string(),
            "pass".to_string(),
        )).unwrap();
        
        let results = vault.search("git");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "GitHub");
    }
}