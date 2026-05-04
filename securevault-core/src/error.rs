//! SecureVault Error Types

use thiserror::Error;

/// SecureVault Result type
pub type Result<T> = std::result::Result<T, Error>;

/// SecureVault Error variants
#[derive(Error, Debug)]
pub enum Error {
    /// Cryptographic operation failed
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Invalid key or password
    #[error("Invalid key or password: {0}")]
    InvalidKey(String),

    /// Vault is locked
    #[error("Vault is locked")]
    VaultLocked,

    /// Vault is already unlocked
    #[error("Vault is already unlocked")]
    VaultUnlocked,

    /// Entry not found
    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    /// Invalid entry data
    #[error("Invalid entry: {0}")]
    InvalidEntry(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// P2P sync error
    #[error("Sync error: {0}")]
    Sync(String),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Invalid OAuth token
    #[error("Invalid OAuth token: {0}")]
    InvalidOAuthToken(String),

    /// Invalid passkey
    #[error("Invalid passkey: {0}")]
    InvalidPasskey(String),

    /// TOTP error
    #[error("TOTP error: {0}")]
    TOTP(String),

    /// Autofill error
    #[error("Autofill error: {0}")]
    Autofill(String),

    /// Behavioral analysis error
    #[error("Behavioral analysis error: {0}")]
    Behavior(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    Config(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Parse error
    #[error("Parse error: {0}")]
    Parse(String),
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Crypto(format!("Base64 decode error: {}", e))
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization(format!("JSON error: {}", e))
    }
}

impl From<uuid::Error> for Error {
    fn from(e: uuid::Error) -> Self {
        Error::Parse(format!("UUID error: {}", e))
    }
}

impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error::Crypto("Ring cryptographic error".to_string())
    }
}

impl From<liboqs::Error> for Error {
    fn from(e: liboqs::Error) -> Self {
        Error::Crypto(format!("liboqs error: {:?}", e))
    }
}