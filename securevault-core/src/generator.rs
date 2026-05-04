//! Password Generator
//!
//! Generates secure passwords with configurable options

use crate::crypto::rng;
use crate::error::Result;

/// Password generator configuration
#[derive(Debug, Clone)]
pub struct PasswordOptions {
    /// Length of the password
    pub length: usize,
    /// Include uppercase letters (A-Z)
    pub uppercase: bool,
    /// Include lowercase letters (a-z)
    pub lowercase: bool,
    /// Include numbers (0-9)
    pub numbers: bool,
    /// Include symbols
    pub symbols: bool,
    /// Custom symbol set (if symbols enabled)
    pub custom_symbols: Option<String>,
    /// Exclude ambiguous characters (0, O, l, 1, I)
    pub exclude_ambiguous: bool,
    /// Require at least one character from each selected set
    pub require_each_set: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            custom_symbols: None,
            exclude_ambiguous: false,
            require_each_set: true,
        }
    }
}

/// Character sets
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const NUMBERS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";
const AMBIGUOUS: &[u8] = b"0O1lI";

impl PasswordOptions {
    /// Create password from options
    pub fn generate(&self) -> Result<String> {
        let charset = self.build_charset()?;
        
        if charset.is_empty() {
            return Err(crate::error::Error::Config("No character sets selected".to_string()));
        }
        
        if self.length < 4 {
            return Err(crate::error::Error::Config("Password length must be at least 4".to_string()));
        }
        
        let mut password = Vec::with_capacity(self.length);
        
        // If require_each_set, first ensure at least one from each set
        if self.require_each_set {
            self.add_required_chars(&mut password)?;
        }
        
        // Fill remaining with random characters
        while password.len() < self.length {
            let idx = rng::random_in_range(0, charset.len())?;
            password.push(charset[idx] as char);
        }
        
        // Shuffle the password
        if self.require_each_set {
            self.shuffle(&mut password);
        }
        
        Ok(password.iter().collect())
    }

    fn build_charset(&self) -> Result<Vec<u8>> {
        let mut charset = Vec::new();
        
        if self.uppercase {
            charset.extend_from_slice(UPPERCASE);
        }
        if self.lowercase {
            charset.extend_from_slice(LOWERCASE);
        }
        if self.numbers {
            charset.extend_from_slice(NUMBERS);
        }
        if self.symbols {
            if let Some(ref custom) = self.custom_symbols {
                charset.extend_from_slice(custom.as_bytes());
            } else {
                charset.extend_from_slice(SYMBOLS);
            }
        }
        
        // Remove ambiguous characters if requested
        if self.exclude_ambiguous {
            charset.retain(|c| !AMBIGUOUS.contains(c));
        }
        
        Ok(charset)
    }

    fn add_required_chars(&self, password: &mut Vec<char>) -> Result<()> {
        // Add one character from each enabled set
        
        if self.uppercase {
            let chars: Vec<char> = UPPERCASE.iter()
                .filter(|c| !self.exclude_ambiguous || !AMBIGUOUS.contains(*c))
                .map(|c| *c as char)
                .collect();
            if let Some(c) = rng::random_element(&chars)? {
                password.push(c);
            }
        }
        
        if self.lowercase {
            let chars: Vec<char> = LOWERCASE.iter()
                .filter(|c| !self.exclude_ambiguous || !AMBIGUOUS.contains(*c))
                .map(|c| *c as char)
                .collect();
            if let Some(c) = rng::random_element(&chars)? {
                password.push(c);
            }
        }
        
        if self.numbers {
            let chars: Vec<char> = NUMBERS.iter()
                .filter(|c| !self.exclude_ambiguous || !AMBIGUOUS.contains(*c))
                .map(|c| *c as char)
                .collect();
            if let Some(c) = rng::random_element(&chars)? {
                password.push(c);
            }
        }
        
        if self.symbols {
            if let Some(ref custom) = self.custom_symbols {
                let chars: Vec<char> = custom.chars().collect();
                if let Some(c) = rng::random_element(&chars)? {
                    password.push(c);
                }
            } else {
                let chars: Vec<char> = SYMBOLS.iter().map(|c| *c as char).collect();
                if let Some(c) = rng::random_element(&chars)? {
                    password.push(c);
                }
            }
        }
        
        Ok(())
    }

    fn shuffle(&self, password: &mut Vec<char>) {
        // Fisher-Yates shuffle
        let len = password.len();
        for i in (1..len).rev() {
            let j = rng::random_in_range(0, i + 1).unwrap();
            password.swap(i, j);
        }
    }

    /// Preset: Strong password (all characters, 20 chars)
    pub fn strong() -> Self {
        Self::default()
    }

    /// Preset: PIN (numbers only, 4-6 digits)
    pub fn pin(length: usize) -> Self {
        Self {
            length: length.max(4).min(6),
            uppercase: false,
            lowercase: false,
            numbers: true,
            symbols: false,
            exclude_ambiguous: true,
            require_each_set: false,
            ..Default::default()
        }
    }

    /// Preset: Passphrase (words separated by hyphen)
    pub fn passphrase(word_count: usize) -> String {
        let words = [
            "apple", "brave", "cloud", "delta", "eagle", "focus", "grace", "house",
            "image", "joyful", "kite", "lemon", "mountain", "noble", "ocean", "peace",
            "quiet", "river", "sunny", "tiger", "unity", "vivid", "water", "xenon",
            "yellow", "zebra", "anchor", "bridge", "castle", "dragon", "ember", "forest",
        ];
        
        let mut passphrase = Vec::new();
        
        for _ in 0..word_count {
            if let Some(word) = rng::random_element(&words).ok() {
                if !passphrase.is_empty() {
                    passphrase.push('-');
                }
                // Capitalize first letter
                let mut chars = word.chars();
                if let Some(first) = chars.next() {
                    passphrase.push(first.to_ascii_uppercase());
                    passphrase.extend(chars);
                }
            }
        }
        
        passphrase.iter().collect()
    }

    /// Calculate password strength (0-100)
    pub fn calculate_strength(password: &str) -> u8 {
        let len = password.len();
        
        let mut has_lower = false;
        let mut has_upper = false;
        let mut has_digit = false;
        let mut has_special = false;
        
        for c in password.chars() {
            if c.is_ascii_lowercase() { has_lower = true; }
            else if c.is_ascii_uppercase() { has_upper = true; }
            else if c.is_ascii_digit() { has_digit = true; }
            else { has_special = true; }
        }
        
        let charset_size = [has_lower, has_upper, has_digit, has_special]
            .iter()
            .filter(|&&x| x)
            .count();
        
        // Base score from length
        let mut score = if len < 8 { 0 }
        else if len < 12 { 20 }
        else if len < 16 { 40 }
        else if len < 20 { 60 }
        else { 80 };
        
        // Bonus for charset variety
        score += (charset_size as u8) * 5;
        
        // Cap at 100
        score.min(100) as u8
    }

    /// Get strength label
    pub fn strength_label(strength: u8) -> &'static str {
        if strength < 25 { "Very Weak" }
        else if strength < 50 { "Weak" }
        else if strength < 75 { "Good" }
        else { "Strong" }
    }
}

/// Generate password with default options
pub fn generate_password() -> Result<String> {
    PasswordOptions::default().generate()
}

/// Generate password with custom length
pub fn generate_password_length(length: usize) -> Result<String> {
    PasswordOptions {
        length,
        ..Default::default()
    }.generate()
}

/// Generate PIN
pub fn generate_pin(digits: usize) -> Result<String> {
    PasswordOptions::pin(digits).generate()
}

/// Generate passphrase
pub fn generate_passphrase(word_count: usize) -> String {
    PasswordOptions::passphrase(word_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_default() {
        let password = generate_password().unwrap();
        
        assert_eq!(password.len(), 20);
        // Should contain at least some variety
        assert!(password.chars().any(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_generate_pin() {
        let pin = generate_pin(6).unwrap();
        
        assert_eq!(pin.len(), 6);
        assert!(pin.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_passphrase() {
        let phrase = generate_passphrase(4);
        
        assert!(phrase.len() > 0);
        assert!(phrase.contains('-'));
    }

    #[test]
    fn test_strength_calculation() {
        assert_eq!(PasswordOptions::calculate_strength("abc"), 0);
        assert_eq!(PasswordOptions::calculate_strength("abcdefgh"), 20);
        assert_eq!(PasswordOptions::calculate_strength("Abcd1234!@#$"), 80);
    }

    #[test]
    fn test_custom_options() {
        let opts = PasswordOptions {
            length: 16,
            uppercase: true,
            lowercase: true,
            numbers: false,
            symbols: false,
            exclude_ambiguous: true,
            require_each_set: false,
            custom_symbols: None,
        };
        
        let password = opts.generate().unwrap();
        
        assert_eq!(password.len(), 16);
        assert!(password.chars().all(|c| c.is_ascii_alphabetic()));
    }
}