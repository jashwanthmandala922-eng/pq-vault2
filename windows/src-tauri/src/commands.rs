use serde::{Deserialize, Serialize};
use crate::vault::{self, VaultEntry};
use crate::security::{validate_command_input, validate_password_strength, validate_url, sanitize_string, ValidationError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPeer {
    pub id: String,
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandError {
    pub code: String,
    pub message: String,
}

impl From<ValidationError> for CommandError {
    fn from(err: ValidationError) -> Self {
        match err {
            ValidationError::InvalidInput { field, reason } => CommandError {
                code: "INVALID_INPUT".to_string(),
                message: format!("Invalid {}: {}", field, reason),
            },
            ValidationError::InputTooLong { field, max, actual } => CommandError {
                code: "INPUT_TOO_LONG".to_string(),
                message: format!("{} is too long: {} > max {}", field, actual, max),
            },
            ValidationError::InputTooShort { field, min, actual } => CommandError {
                code: "INPUT_TOO_SHORT".to_string(),
                message: format!("{} is too short: {} < min {}", field, actual, min),
            },
            ValidationError::InvalidFormat { field, expected } => CommandError {
                code: "INVALID_FORMAT".to_string(),
                message: format!("{} must be {}", field, expected),
            },
            ValidationError::ForbiddenValue { field, value } => CommandError {
                code: "FORBIDDEN_VALUE".to_string(),
                message: format!("Invalid {}: {}", field, value),
            },
            ValidationError::RateLimited { retry_after } => CommandError {
                code: "RATE_LIMITED".to_string(),
                message: format!("Rate limited, retry after {} seconds", retry_after),
            },
            ValidationError::Unauthorized => CommandError {
                code: "UNAUTHORIZED".to_string(),
                message: "Unauthorized access".to_string(),
            },
        }
    }
}

impl From<vault::VaultError> for CommandError {
    fn from(err: vault::VaultError) -> Self {
        match err {
            vault::VaultError::Locked => CommandError {
                code: "VAULT_LOCKED".to_string(),
                message: "Vault is locked".to_string(),
            },
            vault::VaultError::InvalidPassword => CommandError {
                code: "INVALID_PASSWORD".to_string(),
                message: "Invalid master password".to_string(),
            },
            vault::VaultError::NotFound(msg) => CommandError {
                code: "NOT_FOUND".to_string(),
                message: msg,
            },
            _ => CommandError {
                code: "VAULT_ERROR".to_string(),
                message: err.to_string(),
            },
        }
    }
}

/// Unlock the vault with master password
#[tauri::command]
pub fn unlock_vault(password: String) -> Result<String, CommandError> {
    let payload = serde_json::json!({ "password": &password });
    validate_command_input("unlock_vault", &payload)
        .map_err(|e| CommandError::from(e))?;

    vault::vault_unlock(password)
        .map_err(|e| CommandError::from(e))
}

/// Lock the vault
#[tauri::command]
pub fn lock_vault() -> Result<(), CommandError> {
    vault::vault_lock()
        .map_err(|e| CommandError::from(e))
}

/// Create a new vault
#[tauri::command]
pub fn create_vault(password: String) -> Result<String, CommandError> {
    validate_command_input("create_vault", &serde_json::json!({ "password": &password }))
        .map_err(|e| CommandError::from(e))?;

    vault::vault_create(password)
        .map_err(|e| CommandError::from(e))
}

/// Add a password entry
#[tauri::command]
pub fn add_entry(
    title: String,
    url: Option<String>,
    username: Option<String>,
    password: String,
    notes: Option<String>,
) -> Result<VaultEntry, CommandError> {
    let mut payload = serde_json::json!({
        "title": &title,
        "password": &password
    });
    if let Some(ref u) = url { payload["url"] = serde_json::json!(u); }
    if let Some(ref u) = username { payload["username"] = serde_json::json!(u); }

    validate_command_input("add_entry", &payload)
        .map_err(|e| CommandError::from(e))?;

    if let Some(ref u) = url {
        if !validate_url(u) {
            return Err(CommandError {
                code: "INVALID_URL".to_string(),
                message: "URL must be a valid http/https/ftp URL".to_string(),
            });
        }
    }

    let safe_title = sanitize_string(&title);
    let safe_username = username.map(|u| sanitize_string(&u));
    let safe_url = url.map(|u| sanitize_string(&u));
    let safe_notes = notes.map(|n| sanitize_string(&n));

    vault::vault_add_entry(safe_title, safe_url, safe_username, password, safe_notes)
        .map_err(|e| CommandError::from(e))
}

/// Get all vault entries
#[tauri::command]
pub fn get_entries() -> Result<Vec<VaultEntry>, CommandError> {
    Ok(vault::vault_get_entries())
}

/// Generate a secure password
#[tauri::command]
pub fn generate_password(
    length: usize,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    symbols: bool,
) -> Result<String, CommandError> {
    let payload = serde_json::json!({ "length": length });
    validate_command_input("generate_password", &payload)
        .map_err(|e| CommandError::from(e))?;

    let mut charset = String::new();
    if uppercase { charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
    if lowercase { charset.push_str("abcdefghijklmnopqrstuvwxyz"); }
    if numbers { charset.push_str("0123456789"); }
    if symbols { charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?"); }

    if charset.is_empty() {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
    }

    let charset: Vec<char> = charset.chars().collect();
    let mut rng = rand::thread_rng();
    let password: String = (0..length)
        .map(|_| charset[rng.gen_range(0..charset.len())])
        .collect();

    Ok(password)
}

/// Start P2P discovery
#[tauri::command]
pub fn start_sync() -> Result<(), CommandError> {
    log::info!("Starting P2P sync");
    Ok(())
}

/// Get discovered peers
#[tauri::command]
pub fn get_peers() -> Result<Vec<SyncPeer>, CommandError> {
    log::info!("Getting sync peers");
    Ok(vec![])
}