//! Behavioral Profile Module

use super::{KeystrokeProfile, TouchProfile, MouseProfile};
use crate::vault::entry::EncryptedField;
use crate::error::Result;

/// User's behavioral profile (stored encrypted)
#[derive(Debug, Clone)]
pub struct BehavioralProfile {
    /// Profile ID
    pub id: String,
    /// Keystroke profile
    pub keystroke: Option<KeystrokeProfile>,
    /// Touch profile (mobile)
    pub touch: Option<TouchProfile>,
    /// Mouse profile (desktop)
    pub mouse: Option<MouseProfile>,
    /// Combined confidence score
    pub confidence: f32,
    /// Number of sessions used to build profile
    pub session_count: u32,
    /// Profile creation timestamp
    pub created_at: u64,
    /// Last updated timestamp
    pub last_updated: u64,
    /// Is profile ready for verification
    pub ready: bool,
}

impl Default for BehavioralProfile {
    fn default() -> Self {
        Self {
            id: String::new(),
            keystroke: None,
            touch: None,
            mouse: None,
            confidence: 0.0,
            session_count: 0,
            created_at: 0,
            last_updated: 0,
            ready: false,
        }
    }
}

impl BehavioralProfile {
    /// Create new empty profile
    pub fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            created_at: now,
            last_updated: now,
            ..Default::default()
        }
    }

    /// Update profile with new session data
    pub fn update(&mut self, session: &super::BehavioralSession) {
        // Update keystroke profile
        if !session.keystrokes.is_empty() {
            let new_profile = super::KeystrokeAnalyzer::analyze(&session.keystrokes);
            self.keystroke = Some(new_profile);
        }
        
        // Update touch profile
        if !session.touch_samples.is_empty() {
            let new_profile = super::GestureAnalyzer::analyze_touch(&session.touch_samples);
            self.touch = Some(new_profile);
        }
        
        // Update mouse profile
        if !session.mouse_samples.is_empty() {
            let new_profile = super::GestureAnalyzer::analyze_mouse(&session.mouse_samples);
            self.mouse = Some(new_profile);
        }
        
        self.session_count += 1;
        self.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Mark ready after sufficient sessions
        self.ready = self.session_count >= 5;
        self.confidence = self.calculate_confidence();
    }

    /// Calculate combined confidence
    fn calculate_confidence(&self) -> f32 {
        let mut scores = Vec::new();
        
        if self.keystroke.is_some() {
            // Higher score with more sessions
            let base = 0.5;
            let bonus = (self.session_count as f32 / 20.0).min(0.4);
            scores.push(base + bonus);
        }
        
        if self.touch.is_some() {
            scores.push(0.7);
        }
        
        if self.mouse.is_some() {
            scores.push(0.6);
        }
        
        if scores.is_empty() {
            0.0
        } else {
            scores.iter().sum::<f32>() / scores.len() as f32
        }
    }

    /// Verify current session against profile
    pub fn verify(&self, session: &super::BehavioralSession) -> f32 {
        let mut total_score = 0.0;
        let mut count = 0;
        
        // Keystroke verification
        if let Some(ref profile) = self.keystroke {
            if !session.keystrokes.is_empty() {
                let score = super::KeystrokeAnalyzer::compare(&session.keystrokes, profile);
                total_score += score;
                count += 1;
            }
        }
        
        // Touch verification
        if let Some(ref profile) = self.touch {
            if !session.touch_samples.is_empty() {
                let score = super::GestureAnalyzer::compare_touch(&session.touch_samples, profile);
                total_score += score;
                count += 1;
            }
        }
        
        // Mouse verification
        if let Some(ref profile) = self.mouse {
            if !session.mouse_samples.is_empty() {
                let score = super::GestureAnalyzer::compare_mouse(&session.mouse_samples, profile);
                total_score += score;
                count += 1;
            }
        }
        
        if count == 0 {
            0.5 // Neutral if no data to compare
        } else {
            total_score / count as f32
        }
    }
}

/// Profile data for serialization
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProfileData {
    pub keystroke: Option<KeystrokeProfile>,
    pub touch: Option<TouchProfile>,
    pub mouse: Option<MouseProfile>,
    pub session_count: u32,
    pub created_at: u64,
    pub last_updated: u64,
}

impl From<&BehavioralProfile> for ProfileData {
    fn from(profile: &BehavioralProfile) -> Self {
        Self {
            keystroke: profile.keystroke.clone(),
            touch: profile.touch.clone(),
            mouse: profile.mouse.clone(),
            session_count: profile.session_count,
            created_at: profile.created_at,
            last_updated: profile.last_updated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_creation() {
        let profile = BehavioralProfile::new();
        
        assert!(!profile.id.is_empty());
        assert!(!profile.ready);
    }

    #[test]
    fn test_confidence_calculation() {
        let mut profile = BehavioralProfile::new();
        
        // Initially low confidence
        assert_eq!(profile.confidence, 0.0);
        
        // After sessions, confidence increases
        profile.session_count = 5;
        profile.keystroke = Some(KeystrokeProfile::default());
        
        profile.confidence = profile.calculate_confidence();
        
        assert!(profile.confidence > 0.0);
    }

    #[test]
    fn test_profile_ready() {
        let mut profile = BehavioralProfile::new();
        
        assert!(!profile.ready);
        
        profile.session_count = 5;
        profile.keystroke = Some(KeystrokeProfile::default());
        
        profile.ready = profile.session_count >= 5;
        
        assert!(profile.ready);
    }
}