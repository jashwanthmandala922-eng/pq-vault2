//! TOTP Code Generator

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::{Error, Result};

/// HMAC type for TOTP
pub type HmacSha1 = Hmac<Sha1>;
pub type HmacSha256 = Hmac<Sha256>;
pub type HmacSha512 = Hmac<Sha512>;

/// TOTP Algorithm
#[derive(Clone, Copy, Debug)]
pub enum TOTPAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

/// TOTP code with metadata
pub struct TOTPCode {
    pub code: String,
    pub remaining_seconds: u32,
    pub period: u32,
}

/// Generate TOTP code
pub fn generate_totp(
    secret: &[u8],
    time_step: u64,
    digits: u8,
    algorithm: &TOTPAlgorithm,
) -> Result<String> {
    // Convert time step to big-endian 8 bytes
    let counter = time_step.to_be_bytes();
    
    // Generate HMAC
    let hmac_result = match algorithm {
        TOTPAlgorithm::SHA1 => {
            let mut mac = HmacSha1::new_from_slice(secret)
                .map_err(|e| Error::TOTP(format!("Invalid HMAC key: {}", e)))?;
            mac.update(&counter);
            mac.finalize().into_bytes().to_vec()
        }
        TOTPAlgorithm::SHA256 => {
            let mut mac = HmacSha256::new_from_slice(secret)
                .map_err(|e| Error::TOTP(format!("Invalid HMAC key: {}", e)))?;
            mac.update(&counter);
            mac.finalize().into_bytes().to_vec()
        }
        TOTPAlgorithm::SHA512 => {
            let mut mac = HmacSha512::new_from_slice(secret)
                .map_err(|e| Error::TOTP(format!("Invalid HMAC key: {}", e)))?;
            mac.update(&counter);
            mac.finalize().into_bytes().to_vec()
        }
    };
    
    // Dynamic truncation
    let offset = (hmac_result[hmac_result.len() - 1] & 0x0F) as usize;
    
    let binary = ((hmac_result[offset] & 0x7F) as u32) << 24
        | (hmac_result[offset + 1] as u32) << 16
        | (hmac_result[offset + 2] as u32) << 8
        | (hmac_result[offset + 3] as u32);
    
    // Generate code with specified digits
    let modulo = 10u32.pow(digits as u32);
    let code = (binary % modulo).to_string();
    
    // Pad with leading zeros if needed
    Ok(format!("{:0>width$}", code, width = digits as usize))
}

/// Generate TOTP for current time
pub fn generate_current_totp(
    secret: &[u8],
    digits: u8,
    period: u32,
    algorithm: &TOTPAlgorithm,
) -> Result<TOTPCode> {
    let now = chrono::Utc::now().timestamp() as u64;
    let time_step = now / period as u64;
    let remaining = period - (now % period as u64) as u32;
    
    let code = generate_totp(secret, time_step, digits, algorithm)?;
    
    Ok(TOTPCode {
        code,
        remaining_seconds: remaining,
        period,
    })
}

/// Verify a TOTP code
pub fn verify_totp(
    secret: &[u8],
    code: &str,
    time_step: u64,
    digits: u8,
    algorithm: &TOTPAlgorithm,
    // Allow codes from adjacent time steps for clock drift
    window: u64,
) -> Result<bool> {
    // Check current and adjacent time steps
    for delta in 0..=window {
        for step in [time_step - delta, time_step + delta] {
            let generated = generate_totp(secret, step, digits, algorithm)?;
            if generated == code {
                return Ok(true);
            }
        }
    }
    
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_sha1() {
        // RFC 6238 test vector
        let secret = b"12345678901234567890";
        let time_step = 1; // 59 seconds from epoch
        
        let code = generate_totp(secret, time_step, 6, &TOTPAlgorithm::SHA1).unwrap();
        
        // Expected: 287082 (from RFC 6238)
        assert_eq!(code, "287082");
    }

    #[test]
    fn test_totp_sha256() {
        let secret = b"12345678901234567890";
        let time_step = 1;
        
        let code = generate_totp(secret, time_step, 6, &TOTPAlgorithm::SHA256).unwrap();
        
        // Should be 6 digits
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_verify_valid_code() {
        let secret = b"test_secret";
        
        // Get current code
        let time_step = chrono::Utc::now().timestamp() as u64 / 30;
        let code = generate_totp(secret, time_step, 6, &TOTPAlgorithm::SHA256).unwrap();
        
        // Should verify
        let valid = verify_totp(secret, &code, time_step, 6, &TOTPAlgorithm::SHA256, 1).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_invalid_code() {
        let secret = b"test_secret";
        let time_step = chrono::Utc::now().timestamp() as u64 / 30;
        
        let valid = verify_totp(secret, "000000", time_step, 6, &TOTPAlgorithm::SHA256, 1).unwrap();
        
        assert!(!valid);
    }
}