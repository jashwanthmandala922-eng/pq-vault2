use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, PasswordHasher, password::Password};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use directories::ProjectDirs;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use thiserror::Error;
use zeroize::Zeroizing;
use crate::security::{validate_command_input, validate_password_strength, validate_url, sanitize_string, ValidationError};

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Vault is locked")]
    Locked,
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: String,
    pub title: String,
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: String,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub favorite: bool,
    pub entry_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedVault {
    salt: String,
    nonce: String,
    ciphertext: String,
    version: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultData {
    entries: HashMap<String, VaultEntry>,
    created_at: DateTime<Utc>,
    last_modified: DateTime<Utc>,
}

pub struct VaultState {
    is_unlocked: bool,
    encryption_key: Option<Zeroizing<[u8; 32]>>,
    data: Option<VaultData>,
    path: PathBuf,
}

impl VaultState {
    pub fn new() -> Self {
        let path = get_vault_path();
        Self {
            is_unlocked: false,
            encryption_key: None,
            data: None,
            path,
        }
    }
}

fn get_vault_path() -> PathBuf {
    if let Some(proj_dirs) = ProjectDirs::from("com", "quantvault", "pq-vault") {
        let data_dir = proj_dirs.data_dir();
        fs::create_dir_all(data_dir).ok();
        data_dir.join("vault.enc")
    } else {
        PathBuf::from("vault.enc")
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let argon2 = Argon2::default();
    let password = Password::new(password.as_bytes());
    
    let mut key = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(password, salt, &mut *key)
        .map_err(|e| VaultError::Encryption(format!("Key derivation failed: {}", e)))?;
    
    Ok(key)
}

fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

fn encrypt_data(key: &[u8; 32], data: &VaultData) -> Result<EncryptedVault, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;
    
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let plaintext = serde_json::to_string(data)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;
    
    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| VaultError::Encryption(e.to_string()))?;
    
    Ok(EncryptedVault {
        salt: BASE64.encode(key),
        nonce: BASE64.encode(nonce_bytes),
        ciphertext: BASE64.encode(ciphertext),
        version: 1,
    })
}

fn decrypt_data(key: &[u8; 32], encrypted: &EncryptedVault) -> Result<VaultData, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;
    
    let nonce_bytes = BASE64.decode(&encrypted.nonce)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = BASE64.decode(&encrypted.ciphertext)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;
    
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| VaultError::InvalidPassword)?;
    
    let data: VaultData = serde_json::from_slice(&plaintext)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;
    
    Ok(data)
}

pub fn create_vault(password: &str) -> Result<(), VaultError> {
    validate_password_strength(password).map_err(|e| VaultError::Encryption(e.to_string()))?;
    
    let salt = generate_salt();
    let key = derive_key(password, &salt)?;
    
    let data = VaultData {
        entries: HashMap::new(),
        created_at: Utc::now(),
        last_modified: Utc::now(),
    };
    
    let mut encrypted = encrypt_data(&key, &data)?;
    encrypted.salt = BASE64.encode(salt);
    
    let path = get_vault_path();
    let json = serde_json::to_string_pretty(&encrypted)
        .map_err(|e| VaultError::Storage(e.to_string()))?;
    fs::write(&path, json)
        .map_err(|e| VaultError::Storage(e.to_string()))?;
    
    log::info!("Vault created successfully");
    Ok(())
}

pub fn unlock_vault(password: &str) -> Result<VaultData, VaultError> {
    let path = get_vault_path();
    
    if !path.exists() {
        return Err(VaultError::NotFound("No vault found. Create one first.".to_string()));
    }
    
    let content = fs::read_to_string(&path)
        .map_err(|e| VaultError::Storage(e.to_string()))?;
    
    let mut encrypted: EncryptedVault = serde_json::from_str(&content)
        .map_err(|e| VaultError::Storage(e.to_string()))?;
    
    let salt = BASE64.decode(&encrypted.salt)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;
    let key = derive_key(password, &salt)?;
    
    let data = decrypt_data(&key, &encrypted)?;
    
    log::info!("Vault unlocked successfully");
    Ok(data)
}

pub fn lock_vault() -> Result<(), VaultError> {
    log::info!("Vault locked");
    Ok(())
}

pub fn add_entry(
    title: &str,
    url: Option<&str>,
    username: Option<&str>,
    password: &str,
    notes: Option<&str>,
) -> Result<VaultEntry, VaultError> {
    let entry = VaultEntry {
        id: uuid::Uuid::new_v4().to_string(),
        title: title.to_string(),
        url: url.map(|s| s.to_string()),
        username: username.map(|s| s.to_string()),
        password: password.to_string(),
        notes: notes.map(|s| s.to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        favorite: false,
        entry_type: "login".to_string(),
    };
    
    log::info!("Entry added: {}", entry.title);
    Ok(entry)
}

pub fn get_entries() -> Vec<VaultEntry> {
    vec![]
}

lazy_static::lazy_static! {
    static ref VAULT: Mutex<VaultState> = Mutex::new(VaultState::new());
}

pub fn vault_create(password: String) -> Result<String, VaultError> {
    create_vault(&password)?;
    Ok("Vault created successfully".to_string())
}

pub fn vault_unlock(password: String) -> Result<String, VaultError> {
    let data = unlock_vault(&password)?;
    let mut vault = VAULT.lock().unwrap();
    vault.is_unlocked = true;
    vault.data = Some(data);
    Ok("Vault unlocked".to_string())
}

pub fn vault_lock() -> Result<(), VaultError> {
    let mut vault = VAULT.lock().unwrap();
    vault.is_unlocked = false;
    vault.data = None;
    vault.encryption_key = None;
    lock_vault()
}

pub fn vault_add_entry(
    title: String,
    url: Option<String>,
    username: Option<String>,
    password: String,
    notes: Option<String>,
) -> Result<VaultEntry, VaultError> {
    let entry = add_entry(
        &title,
        url.as_deref(),
        username.as_deref(),
        &password,
        notes.as_deref(),
    )?;
    Ok(entry)
}

pub fn vault_get_entries() -> Vec<VaultEntry> {
    let vault = VAULT.lock().unwrap();
    if let Some(data) = &vault.data {
        data.entries.values().cloned().collect()
    } else {
        vec![]
    }
}