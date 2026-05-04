//! URL Matching for Autofiller

use crate::error::Result;

/// URL matcher for autofill
pub struct URLMatcher;

impl URLMatcher {
    /// Normalize URL for matching
    pub fn normalize(url: &str) -> String {
        let url = url.to_lowercase();
        
        // Remove trailing slash
        let url = url.trim_end_matches('/');
        
        // Remove www prefix
        let url = url.strip_prefix("www.").unwrap_or(&url);
        
        // Remove port
        if let Some((domain, _)) = url.split_once(':') {
            return domain.to_string();
        }
        
        // Remove path
        if let Some((domain, _)) = url.split_once('/') {
            domain.to_string()
        } else {
            url.to_string()
        }
    }

    /// Extract base domain
    pub fn base_domain(url: &str) -> Option<String> {
        let normalized = Self::normalize(url);
        let parts: Vec<&str> = normalized.split('.').collect();
        
        if parts.len() < 2 {
            return None;
        }
        
        // Get last two parts for base domain
        let base = parts[parts.len() - 2..].join(".");
        Some(base)
    }

    /// Check if two URLs are same site
    pub fn same_site(url1: &str, url2: &str) -> bool {
        Self::base_domain(url1) == Self::base_domain(url2)
    }

    /// Calculate similarity score (0-1)
    pub fn similarity(url1: &str, url2: &str) -> f32 {
        let norm1 = Self::normalize(url1);
        let norm2 = Self::normalize(url2);
        
        if norm1 == norm2 {
            return 1.0;
        }
        
        // Character-based similarity
        let chars1: Vec<char> = norm1.chars().collect();
        let chars2: Vec<char> = norm2.chars().collect();
        
        let max_len = chars1.len().max(chars2.len());
        if max_len == 0 {
            return 0.0;
        }
        
        // Count matching positions
        let matches = chars1.iter()
            .zip(chars2.iter())
            .filter(|(a, b)| a == b)
            .count();
        
        matches as f32 / max_len as f32
    }

    /// Find potential matches with similarity threshold
    pub fn find_matches(url: &str, candidates: &[String], threshold: f32) -> Vec<(String, f32)> {
        candidates.iter()
            .map(|c| (c.clone(), Self::similarity(url, c)))
            .filter(|(_, score)| *score >= threshold)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize() {
        assert_eq!(URLMatcher::normalize("https://github.com/"), "github.com");
        assert_eq!(URLMatcher::normalize("https://www.github.com/login"), "github.com/login");
        assert_eq!(URLMatcher::normalize("https://github.com:443"), "github.com");
    }

    #[test]
    fn test_base_domain() {
        assert_eq!(URLMatcher::base_domain("https://github.com"), Some("github.com".to_string()));
        assert_eq!(URLMatcher::base_domain("https://api.github.com"), Some("github.com".to_string()));
        assert_eq!(URLMatcher::base_domain("https://deep.sub.example.com"), Some("example.com".to_string()));
    }

    #[test]
    fn test_same_site() {
        assert!(URLMatcher::same_site("https://github.com", "https://api.github.com"));
        assert!(URLMatcher::same_site("https://example.com", "https://www.example.com"));
        assert!(!URLMatcher::same_site("https://github.com", "https://gitlab.com"));
    }

    #[test]
    fn test_similarity() {
        assert_eq!(URLMatcher::similarity("github.com", "github.com"), 1.0);
        assert!(URLMatcher::similarity("github.com/login", "github.com") > 0.5);
        assert!(URLMatcher::similarity("github.com", "gitlab.com") < 0.5);
    }

    #[test]
    fn test_find_matches() {
        let candidates = vec![
            "github.com".to_string(),
            "github.com/login".to_string(),
            "gitlab.com".to_string(),
        ];
        
        let matches = URLMatcher::find_matches("github.com/dashboard", &candidates, 0.5);
        
        assert!(matches.len() >= 2);
    }
}