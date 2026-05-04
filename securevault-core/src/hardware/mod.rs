//! Hardware-Backed Key Storage
//!
//! Provides TPM 2.0 (Windows) and Android Keystore integration
//! for device-bound cryptographic keys

pub mod tpm;

#[cfg(target_os = "windows")]
pub use tpm::TpmKeyManager;

#[cfg(not(target_os = "windows"))]
pub mod tpm {
    pub struct TpmKeyManager;

    impl TpmKeyManager {
        pub fn new() -> Self { Self }
        pub fn is_available(&self) -> bool { false }
        pub fn generate_key(&self) -> Result<Vec<u8>, String> { Err("TPM not available".into()) }
        pub fn encrypt(&self, _data: &[u8]) -> Result<Vec<u8>, String> { Err("TPM not available".into()) }
        pub fn decrypt(&self, _data: &[u8]) -> Result<Vec<u8>, String> { Err("TPM not available".into()) }
    }
}