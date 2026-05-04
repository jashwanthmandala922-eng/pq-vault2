//! TOTP URI Parser
//!
//! Parses otpauth:// URIs as per the Google Authenticator format

use crate::error::{Error, Result};

/// Parsed TOTP URI
pub struct ParsedTOTP {
    pub service_name: String,
    pub account_name: String,
    pub secret: String,
    pub issuer: Option<String>,
    pub algorithm: Option<String>,
    pub digits: Option<u8>,
    pub period: Option<u32>,
}

/// Parse an otpauth:// URI
pub struct TOTPUriParser;

impl TOTPUriParser {
    /// Parse otpauth://totp/ or otpauth://hotp/ URI
    pub fn parse(uri: &str) -> Result<ParsedTOTP> {
        // Must start with otpauth://
        if !uri.starts_with("otpauth://") {
            return Err(Error::TOTP("Invalid otpauth URI: missing prefix".to_string()));
        }
        
        // Parse scheme and type
        let remainder = &uri[10..]; // Skip "otpauth://"
        
        let (type_part, path_part) = remainder
            .split_once('/')
            .ok_or_else(|| Error::TOTP("Invalid otpauth URI: missing type".to_string()))?;
        
        let _type = type_part.to_lowercase();
        
        // Validate type
        if _type != "totp" && _type != "hotp" {
            return Err(Error::TOTP(format!("Unsupported type: {}", _type)));
        }
        
        // Parse path (label)
        let path = path_part
            .split_once('?')
            .map(|(p, _)| p)
            .unwrap_or(path_part);
        
        // Decode URL encoding and extract service:account
        let (issuer, service_name, account_name) = Self::parse_label(path)?;
        
        // Parse query parameters
        let mut secret = None;
        let mut algorithm = None;
        let mut digits = None;
        let mut period = None;
        let mut issuer_param = None;
        
        if let Some((_, query)) = path_part.split_once('?') {
            for param in query.split('&') {
                if let Some((key, value)) = param.split_once('=') {
                    let value = url_decode(value);
                    
                    match key.to_lowercase().as_str() {
                        "secret" => secret = Some(value),
                        "algorithm" => algorithm = Some(value),
                        "digits" => digits = value.parse().ok(),
                        "period" => period = value.parse().ok(),
                        "issuer" => issuer_param = Some(value),
                        _ => {}
                    }
                }
            }
        }
        
        // Get secret (required)
        let secret = secret.ok_or_else(|| Error::TOTP("Missing secret parameter".to_string()))?;
        
        // Use issuer from parameter if path didn't have it
        let final_issuer = issuer.or(issuer_param);
        let final_service = final_issuer.unwrap_or(service_name);
        
        Ok(ParsedTOTP {
            service_name: final_service,
            account_name,
            secret,
            issuer: final_issuer,
            algorithm,
            digits,
            period,
        })
    }

    fn parse_label(path: &str) -> Result<(Option<String>, String, String)> {
        // Format: "Issuer:Account" or just "Account"
        // Or URL encoded: "Issuer%3AAccount" or "Account"
        
        let decoded = url_decode(path);
        
        if let Some((issuer, account)) = decoded.split_once(':') {
            let issuer = if issuer.is_empty() { None } else { Some(issuer.to_string()) };
            let account = account.to_string();
            return Ok((issuer, issuer.unwrap_or_default(), account));
        }
        
        // No issuer, just account
        Ok((None, decoded.clone(), decoded))
    }
}

/// URL decode helper
fn url_decode(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();
    
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    
    result
}

/// Generate otpauth:// URI from TOTP entry
pub fn generate_otpauth_uri(
    service_name: &str,
    account_name: &str,
    secret: &str,
    issuer: Option<&str>,
    algorithm: Option<&str>,
    digits: Option<u8>,
    period: Option<u32>,
) -> String {
    let mut uri = format!(
        "otpauth://totp/{}:{}?secret={}",
        url_encode(service_name),
        url_encode(account_name),
        secret
    );
    
    if let Some(i) = issuer {
        uri.push_str(&format!("&issuer={}", url_encode(i)));
    }
    
    if let Some(a) = algorithm {
        uri.push_str(&format!("&algorithm={}", a.to_uppercase()));
    }
    
    if let Some(d) = digits {
        uri.push_str(&format!("&digits={}", d));
    }
    
    if let Some(p) = period {
        uri.push_str(&format!("&period={}", p));
    }
    
    uri
}

fn url_encode(input: &str) -> String {
    let mut result = String::new();
    for c in input.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
            ' ' => result.push_str("%20"),
            _ => {
                for byte in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_uri() {
        let uri = "otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP";
        
        let parsed = TOTPUriParser::parse(uri).unwrap();
        
        assert_eq!(parsed.service_name, "Test");
        assert_eq!(parsed.account_name, "user@example.com");
        assert_eq!(parsed.secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_parse_with_issuer() {
        let uri = "otpauth://totp/Google%3Auser%40gmail.com?secret=abcd1234&issuer=Google&algorithm=SHA256&digits=8&period=60";
        
        let parsed = TOTPUriParser::parse(uri).unwrap();
        
        assert_eq!(parsed.service_name, "Google");
        assert_eq!(parsed.account_name, "user@gmail.com");
        assert_eq!(parsed.secret, "abcd1234");
        assert_eq!(parsed.algorithm, Some("SHA256".to_string()));
        assert_eq!(parsed.digits, Some(8));
        assert_eq!(parsed.period, Some(60));
    }

    #[test]
    fn test_generate_uri() {
        let uri = generate_otpauth_uri(
            "GitHub",
            "user@email.com",
            "SECRET123",
            Some("GitHub"),
            Some("SHA256"),
            Some(6),
            Some(30),
        );
        
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret=SECRET123"));
        assert!(uri.contains("issuer=GitHub"));
    }

    #[test]
    fn test_url_encoding() {
        assert_eq!(url_encode("test@example"), "test%40example");
        assert_eq!(url_decode("test%40example"), "test@example");
    }
}