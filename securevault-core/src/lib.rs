//! SecureVault Core - Post-Quantum Password Manager
//!
//! A comprehensive password manager with:
//! - Post-quantum cryptography (ML-KEM, ML-DSA)
//! - Encrypted local vault storage
//! - P2P synchronization
//! - Behavioral fingerprinting
//! - Passkey (WebAuthn/FIDO2) support
//! - TOTP Authenticator
//! - Autofiller

pub mod error;
pub mod crypto;
pub mod vault;
pub mod sync;
pub mod behavior;
pub mod passkey;
pub mod totp;
pub mod autofill;
pub mod generator;
pub mod oauth;
pub mod hardware;
pub mod securemem;

// Re-export commonly used types
pub use error::{Error, Result};
pub use vault::{Vault, Entry, EntryType, VaultSettings};
pub use generator::{PasswordOptions, generate_password, generate_passphrase};
pub use hardware::TpmKeyManager;
pub use securemem::{SecureVec, SecureString, SessionKey, MasterKey, SecureZeroize, secure_zeroize};

use log::info;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the SecureVault core library
pub fn init() {
    info!("SecureVault Core v{} initialized", VERSION);
}

/// Get the library version
pub fn version() -> String {
    VERSION.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(version(), "1.0.0");
    }

    #[test]
    fn test_init() {
        init();
    }
}