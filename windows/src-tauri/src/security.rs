//! Secure Command Processing Module
//!
//! Implements strict schema validation and security checks for all IPC commands
//! to prevent malicious payloads from reaching the backend

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Error types for command validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationError {
    InvalidInput { field: String, reason: String },
    InputTooLong { field: String, max: usize, actual: usize },
    InputTooShort { field: String, min: usize, actual: usize },
    InvalidFormat { field: String, expected: String },
    ForbiddenValue { field: String, value: String },
    RateLimited { retry_after: u64 },
    Unauthorized,
}

/// Result type for validated commands
pub type CommandResult<T> = Result<T, ValidationError>;

/// Schema for command input validation
#[allow(dead_code)]
pub trait CommandSchema {
    fn validate(&self) -> CommandResult<()>;
}

/// Input length constraints
pub struct LengthConstraints {
    pub min: usize,
    pub max: usize,
}

/// Field validation rule
pub struct ValidationRule {
    pub field_name: String,
    pub constraints: FieldConstraint,
}

#[allow(dead_code)]
pub enum FieldConstraint {
    String(Option<LengthConstraints>),
    Numeric { min: Option<i64>, max: Option<i64> },
    Boolean,
    Enum(Vec<String>),
}

/// Command validator - enforces schema on all commands
pub struct CommandValidator {
    rules: HashMap<String, Vec<ValidationRule>>,
}

impl CommandValidator {
    pub fn new() -> Self {
        let mut validator = Self { rules: HashMap::new() };
        validator.register_command_rules();
        validator
    }

    fn register_command_rules(&mut self) {
        // Vault unlock - password validation
        self.rules.insert(
            "unlock_vault".to_string(),
            vec![ValidationRule {
                field_name: "password".to_string(),
                constraints: FieldConstraint::String(Some(LengthConstraints { min: 8, max: 128 })),
            }],
        );

        // Vault create - password validation
        self.rules.insert(
            "create_vault".to_string(),
            vec![ValidationRule {
                field_name: "password".to_string(),
                constraints: FieldConstraint::String(Some(LengthConstraints { min: 12, max: 128 })),
            }],
        );

        // Add entry - field validations
        self.rules.insert(
            "add_entry".to_string(),
            vec![
                ValidationRule {
                    field_name: "title".to_string(),
                    constraints: FieldConstraint::String(Some(LengthConstraints { min: 1, max: 100 })),
                },
                ValidationRule {
                    field_name: "url".to_string(),
                    constraints: FieldConstraint::String(Some(LengthConstraints { min: 0, max: 2048 })),
                },
                ValidationRule {
                    field_name: "username".to_string(),
                    constraints: FieldConstraint::String(Some(LengthConstraints { min: 0, max: 256 })),
                },
                ValidationRule {
                    field_name: "password".to_string(),
                    constraints: FieldConstraint::String(Some(LengthConstraints { min: 0, max: 4096 })),
                },
            ],
        );

        // Password generator
        self.rules.insert(
            "generate_password".to_string(),
            vec![ValidationRule {
                field_name: "length".to_string(),
                constraints: FieldConstraint::Numeric { min: Some(4), max: Some(128) },
            }],
        );
    }

    /// Validate command input against registered schema
    pub fn validate(&self, command_name: &str, payload: &serde_json::Value) -> CommandResult<()> {
        let rules = match self.rules.get(command_name) {
            Some(r) => r,
            None => {
                // No rules defined - allow command (should not happen in production)
                log::warn!("No validation rules for command: {}", command_name);
                return Ok(());
            }
        };

        for rule in rules {
            match &rule.constraints {
                FieldConstraint::String(length) => {
                    let field_value = payload.get(&rule.field_name);
                    if let Some(value) = field_value {
                        if let Some(str_val) = value.as_str() {
                            if let Some(len) = length {
                                if str_val.len() < len.min {
                                    return Err(ValidationError::InputTooShort {
                                        field: rule.field_name.clone(),
                                        min: len.min,
                                        actual: str_val.len(),
                                    });
                                }
                                if str_val.len() > len.max {
                                    return Err(ValidationError::InputTooLong {
                                        field: rule.field_name.clone(),
                                        max: len.max,
                                        actual: str_val.len(),
                                    });
                                }
                            }
                        } else if !value.is_null() {
                            return Err(ValidationError::InvalidFormat {
                                field: rule.field_name.clone(),
                                expected: "string".to_string(),
                            });
                        }
                    }
                }
                FieldConstraint::Numeric { min, max } => {
                    if let Some(value) = payload.get(&rule.field_name) {
                        if let Some(num) = value.as_i64() {
                            if let Some(m) = min {
                                if num < *m {
                                    return Err(ValidationError::InvalidInput {
                                        field: rule.field_name.clone(),
                                        reason: format!("Value {} is less than minimum {}", num, m),
                                    });
                                }
                            }
                            if let Some(m) = max {
                                if num > *m {
                                    return Err(ValidationError::InputTooLong {
                                        field: rule.field_name.clone(),
                                        max: *m as usize,
                                        actual: num as usize,
                                    });
                                }
                            }
                        }
                    }
                }
                FieldConstraint::Boolean => {
                    if let Some(value) = payload.get(&rule.field_name) {
                        if !value.is_boolean() {
                            return Err(ValidationError::InvalidFormat {
                                field: rule.field_name.clone(),
                                expected: "boolean".to_string(),
                            });
                        }
                    }
                }
                FieldConstraint::Enum(allowed) => {
                    if let Some(value) = payload.get(&rule.field_name) {
                        if let Some(str_val) = value.as_str() {
                            if !allowed.contains(&str_val.to_string()) {
                                return Err(ValidationError::ForbiddenValue {
                                    field: rule.field_name.clone(),
                                    value: str_val.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Input sanitization - prevent injection attacks
pub fn sanitize_string(input: &str) -> String {
    input
        .chars()
        .filter(|c| {
            // Allow printable ASCII plus common special chars
            c.is_ascii_graphic() || c.is_whitespace()
        })
        .collect()
}

/// URL validation - prevent malformed URLs
pub fn validate_url(url: &str) -> bool {
    if url.is_empty() {
        return true; // Optional URL
    }

    // Basic URL format check
    url.starts_with("http://")
        || url.starts_with("https://")
        || url.starts_with("ftp://")
        || url.starts_with("file://")
}

/// Password strength validation
pub fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    if password.len() < 8 {
        return Err(ValidationError::InputTooShort {
            field: "password".to_string(),
            min: 8,
            actual: password.len(),
        });
    }

    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if !has_upper || !has_lower || !has_digit || !has_special {
        return Err(ValidationError::InvalidInput {
            field: "password".to_string(),
            reason: "Password must contain uppercase, lowercase, digits, and special characters".to_string(),
        });
    }

    Ok(())
}

lazy_static::lazy_static! {
    pub static ref VALIDATOR: CommandValidator = CommandValidator::new();
}

/// Validate and sanitize command input
pub fn validate_command_input(
    command_name: &str,
    payload: &serde_json::Value,
) -> CommandResult<()> {
    VALIDATOR.validate(command_name, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_validation() {
        let result = validate_password_strength("Pass123!");
        assert!(result.is_ok());

        let result = validate_password_strength("weak");
        assert!(result.is_err());
    }

    #[test]
    fn test_url_validation() {
        assert!(validate_url("https://example.com"));
        assert!(validate_url(""));
        assert!(!validate_url("javascript:alert(1)"));
    }

    #[test]
    fn test_command_validation() {
        let validator = CommandValidator::new();
        
        // Valid password
        let payload = serde_json::json!({"password": "TestPass123!"});
        let result = validator.validate("unlock_vault", &payload);
        assert!(result.is_ok());
    }
}