use serde::{Deserialize, Serialize};
use crate::security::{validate_command_input, validate_password_strength, validate_url, sanitize_string, ValidationError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: String,
    pub title: String,
    pub url: Option<String>,
    pub username: Option<String>,
    pub created_at: String,
    pub favorite: bool,
}

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

/// Unlock the vault with master password
#[tauri::command]
pub fn unlock_vault(password: String) -> Result<String, CommandError> {
    // Validate input against schema
    let payload = serde_json::json!({ "password": &password });
    validate_command_input("unlock_vault", &payload)
        .map_err(|e| CommandError::from(e))?;

    // Additional password strength check
    validate_password_strength(&password)
        .map_err(|e| CommandError::from(e))?;

    // Simulate authentication - in production, verify against stored vault
    // For demo, require password to be at least 12 chars for "correct" password
    if password.len() < 12 {
        log::warn!("Failed unlock attempt with short password");
        return Err(CommandError {
            code: "INVALID_CREDENTIALS".to_string(),
            message: "Invalid master password".to_string(),
        });
    }

    log::info!("Vault unlocked successfully");
    Ok("vault_unlocked".to_string())
}

/// Lock the vault
#[tauri::command]
pub fn lock_vault() -> Result<(), CommandError> {
    log::info!("Locking vault");
    Ok(())
}

/// Create a new vault
#[tauri::command]
pub fn create_vault(password: String) -> Result<String, CommandError> {
    // Validate input
    let payload = serde_json::json!({ "password": &password });
    validate_command_input("create_vault", &payload)
        .map_err(|e| CommandError::from(e))?;

    // Strong password validation for new vault
    validate_password_strength(&password)
        .map_err(|e| CommandError::from(e))?;

    log::info!("Creating new vault");
    Ok("vault_created".to_string())
}

/// Add a password entry
#[tauri::command]
pub fn add_entry(
    title: String,
    url: Option<String>,
    username: Option<String>,
    password: String,
) -> Result<VaultEntry, CommandError> {
    // Validate all inputs against schema
    let mut payload = serde_json::json!({
        "title": &title,
        "password": &password
    });
    if let Some(u) = &url {
        payload["url"] = serde_json::json!(u);
    }
    if let Some(u) = &username {
        payload["username"] = serde_json::json!(u);
    }

    validate_command_input("add_entry", &payload)
        .map_err(|e| CommandError::from(e))?;

    // Additional validation
    if let Some(ref u) = url {
        if !validate_url(u) {
            return Err(CommandError {
                code: "INVALID_URL".to_string(),
                message: "URL must be a valid http/https/ftp URL".to_string(),
            });
        }
    }

    // Sanitize inputs to prevent XSS/injection
    let safe_title = sanitize_string(&title);
    let safe_username = username.map(|u| sanitize_string(&u));
    let safe_url = url.map(|u| sanitize_string(&u));

    log::info!("Adding entry: {}", safe_title);
    Ok(VaultEntry {
        id: "new_id".to_string(),
        title: safe_title,
        url: safe_url,
        username: safe_username,
        created_at: "2024-01-01".to_string(),
        favorite: false,
    })
}

/// Get all vault entries
#[tauri::command]
pub fn get_entries() -> Result<Vec<VaultEntry>, CommandError> {
    log::info!("Getting all entries");
    Ok(vec![
        VaultEntry {
            id: "1".to_string(),
            title: "GitHub".to_string(),
            url: Some("https://github.com".to_string()),
            username: Some("user@email.com".to_string()),
            created_at: "2024-01-01".to_string(),
            favorite: true,
        },
        VaultEntry {
            id: "2".to_string(),
            title: "Google".to_string(),
            url: Some("https://google.com".to_string()),
            username: Some("user@gmail.com".to_string()),
            created_at: "2024-01-02".to_string(),
            favorite: false,
        },
    ])
}

/// Generate a password
#[tauri::command]
pub fn generate_password(
    length: usize,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    symbols: bool,
) -> Result<String, CommandError> {
    // Validate numeric input
    let payload = serde_json::json!({ "length": length });
    validate_command_input("generate_password", &payload)
        .map_err(|e| CommandError::from(e))?;

    log::info!("Generating password of length {}", length);

    let mut charset = String::new();
    if uppercase { charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
    if lowercase { charset.push_str("abcdefghijklmnopqrstuvwxyz"); }
    if numbers { charset.push_str("0123456789"); }
    if symbols { charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?"); }

    if charset.is_empty() {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
    }

    let charset: Vec<char> = charset.chars().collect();
    let mut password = String::new();
    for _ in 0..length {
        let idx = rand_index(charset.len());
        password.push(charset[idx]);
    }

    Ok(password)
}

fn rand_index(max: usize) -> usize {
    use rand::Rng;
    if max == 0 {
        return 0;
    }
    let mut rng = rand::thread_rng();
    rng.gen_range(0..max)
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