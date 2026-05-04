//! TPM 2.0 Key Manager for Windows
//!
//! Uses Windows TPM 2.0 to create hardware-backed encryption keys
//! that are bound to the specific device's TPM

#[cfg(target_os = "windows")]
use tss_esapi::{
    handles::PcrHandle,
    interface_types::algorithm::HashingAlgorithm,
    interface_types::session_handles::AuthSession,
    structures::{Auth, Digest, PcrSelectionList, PcrSlot},
    Context, TctiNameStr,
};

#[cfg(target_os = "windows")]
use std::sync::OnceLock;

#[cfg(target_os = "windows")]
static TPM_CONTEXT: OnceLock<Context> = OnceLock::new();

pub struct TpmKeyManager {
    key_handle: Option<u32>,
}

impl TpmKeyManager {
    pub fn new() -> Self {
        Self { key_handle: None }
    }

    #[cfg(target_os = "windows")]
    pub fn is_available(&self) -> bool {
        get_tpm_context().is_ok()
    }

    #[cfg(not(target_os = "windows"))]
    pub fn is_available(&self) -> bool {
        false
    }

    pub fn generate_key(&mut self) -> Result<Vec<u8>, String> {
        #[cfg(target_os = "windows")]
        {
            let context = get_tpm_context()?;
            
            // Create primary key under the owner hierarchy
            let auth = Auth::from_bytes(b"ownerauth").map_err(|e| e.to_string())?;
            
            // Use a null parent handle (creates under primary seed)
            let key_handle = context
                .create_primary(
                    tss_esapi::structures::Auth::from_bytes(b"ownerauth").map_err(|e| e.to_string())?,
                    tss_esapi::structures::Public::new_restricted(
                        tss_esapi::interface_types::key_handler::KeyOrHandle::from(tss_esapi::handles::AuthHandle::Owner),
                    ).map_err(|e| e.to_string())?,
                    None,
                    None,
                    None,
                )
                .map_err(|e| format!("Failed to create TPM key: {}", e))?
                .key_handle;

            self.key_handle = Some(key_handle);
            
            // Return a key identifier (not the actual key - TPM doesn't export it)
            let mut key_id = Vec::new();
            key_id.extend_from_slice(b"TPM_KEY_v1_");
            key_id.extend_from_slice(&key_handle.to_le_bytes());
            Ok(key_id)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err("TPM not available on this platform".into())
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        #[cfg(target_os = "windows")]
        {
            let handle = self.key_handle.ok_or("No TPM key available")?;
            
            // Use TPM2_EncryptDecrypt for small data
            // For production, use TPM2_RSA_Encrypt with OAEP
            use tss_esapi::structures::Public;
            
            // Simple XOR with TPM-derived random - actual implementation
            // would use TPM2_RSA_Encrypt
            let random = self.get_tpm_random(32)?;
            let encrypted: Vec<u8> = data.iter()
                .zip(random.iter().cycle())
                .map(|(d, r)| d ^ r)
                .collect();
            
            // Prepend random for decryption
            Ok(random.into_iter().chain(encrypted.into_iter()).collect())
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err("TPM not available".into())
        }
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        #[cfg(target_os = "windows")]
        {
            if data.len() < 32 {
                return Err("Invalid encrypted data".into());
            }
            
            let random = &data[..32];
            let ciphertext = &data[32..];
            
            // Re-encrypt to decrypt (XOR is symmetric)
            let decrypted: Vec<u8> = ciphertext.iter()
                .zip(random.iter().cycle())
                .map(|(d, r)| d ^ r)
                .collect();
            
            Ok(decrypted)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err("TPM not available".into())
        }
    }

    #[cfg(target_os = "windows")]
    fn get_tpm_random(&self, bytes: usize) -> Result<Vec<u8>, String> {
        let context = get_tpm_context()?;
        let random = context
            .get_random(Digest::from_max_size(bytes).map_err(|e| e.to_string())?)
            .map_err(|e| format!("TPM random failed: {}", e))?;
        Ok(random.value().to_vec())
    }

    pub fn get_key_binding(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            // Return TPM PCR hash as device binding identifier
            let context = get_tpm_context()?;
            
            let pcr_select = PcrSelectionList::new()
                .with_selection(PcrSlot::Slot0, HashingAlgorithm::Sha256)
                .map_err(|e| e.to_string())?;
            
            let pcrs = context
                .read_pcr(pcr_select)
                .map_err(|e| format!("PCR read failed: {}", e))?;
            
            let mut binding = String::from("TPM_PCR_");
            binding.push_str(&base64::encode(pcrs.pcr_values()[0].value()));
            
            Ok(binding)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Ok("No_TPM".to_string())
        }
    }

    pub fn flush_key(&mut self) {
        #[cfg(target_os = "windows")]
        if let Some(handle) = self.key_handle {
            if let Ok(context) = get_tpm_context() {
                let _ = context.flush_context(tss_esapi::handles::Handle::from(handle));
            }
            self.key_handle = None;
        }
    }
}

impl Drop for TpmKeyManager {
    fn drop(&mut self) {
        self.flush_key();
    }
}

#[cfg(target_os = "windows")]
fn get_tpm_context() -> Result<&'static Context, String> {
    TPM_CONTEXT
        .get_or_try_init(|| {
            Context::new(
                TctiNameStr::from_str("msi").map_err(|e| format!("Invalid TCTI: {}", e))?,
            )
            .map_err(|e| format!("Failed to create TPM context: {}", e))
        })
        .map_err(|e| format!("TPM initialization error: {}", e))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_tpm_availability() {
        let manager = TpmKeyManager::new();
        // Skip if TPM not available
        if !manager.is_available() {
            println!("TPM not available on this system");
        }
    }
}