//! Behavioral Fingerprinting Module
//!
//! Analyzes typing patterns, gestures, and mouse movements for identity verification
//! Uses PQ-Vault encryption to protect behavioral profiles
//! ALL data is processed locally - never transmitted
//! Differential Privacy applied to any statistical outputs

pub mod keystroke;
pub mod gesture;
pub mod profile;
pub mod analyzer;
pub mod privacy;  // NEW: Privacy-preserving controls

pub use keystroke::KeystrokeAnalyzer;
pub use gesture::GestureAnalyzer;
pub use profile::{BehavioralProfile, ProfileData};
pub use analyzer::BehavioralAnalyzer;
pub use privacy::{
    PrivacyConfig, 
    DifferentialPrivacy, 
    BehavioralPrivacyController,
    ProtectedBehavioralData,
    DataRetentionPolicy,
    PrivacyAuditLog,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::vault::entry::EncryptedField;
use crate::error::Result;

/// Behavioral session data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralSession {
    /// Session ID
    pub id: Uuid,
    /// Keystroke samples
    pub keystrokes: Vec<KeystrokeSample>,
    /// Touch samples (mobile)
    pub touch_samples: Vec<TouchSample>,
    /// Mouse samples (desktop)
    pub mouse_samples: Vec<MouseSample>,
    /// Session start time
    pub start_time: DateTime<Utc>,
    /// Session end time
    pub end_time: Option<DateTime<Utc>>,
    /// Session type
    pub session_type: SessionType,
}

/// Keystroke sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeSample {
    /// Key pressed
    pub key: char,
    /// Press time (ms from session start)
    pub press_time: u64,
    /// Release time (ms from session start)
    pub release_time: u64,
    /// Inter-key time from previous key (ms)
    pub inter_key_time: Option<u64>,
}

/// Touch sample (mobile)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TouchSample {
    /// X position
    pub x: f32,
    /// Y position
    pub y: f32,
    /// Touch pressure (0-1)
    pub pressure: f32,
    /// Timestamp (ms)
    pub timestamp: u64,
}

/// Mouse sample (desktop)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MouseSample {
    /// X position
    pub x: f32,
    /// Y position
    pub y: f32,
    /// Movement velocity
    pub velocity: f32,
    /// Timestamp (ms)
    pub timestamp: u64,
    /// Event type
    pub event_type: MouseEventType,
}

/// Mouse event type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MouseEventType {
    Move,
    Click,
    Scroll,
}

/// Session type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionType {
    PasswordEntry,
    PINEntry,
    GeneralTyping,
    TouchInteraction,
    MouseInteraction,
}

/// Verification result
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Confidence score (0-1)
    pub confidence: f32,
    /// Threat level
    pub threat_level: ThreatLevel,
    /// Recommended action
    pub action: VerificationAction,
    /// Details
    pub details: String,
}

/// Threat level
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
}

/// Recommended action
#[derive(Debug, Clone, PartialEq)]
pub enum VerificationAction {
    Allow,
    RequireReauth,
    LockVault,
    Alert,
}

impl VerificationResult {
    /// Create from confidence score
    pub fn from_confidence(confidence: f32) -> Self {
        let (threat_level, action) = if confidence >= 0.7 {
            (ThreatLevel::Low, VerificationAction::Allow)
        } else if confidence >= 0.4 {
            (ThreatLevel::Medium, VerificationAction::RequireReauth)
        } else {
            (ThreatLevel::High, VerificationAction::LockVault)
        };
        
        Self {
            confidence,
            threat_level,
            action,
            details: format!("Confidence: {:.1}%", confidence * 100.0),
        }
    }
}

/// Behavioral settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralSettings {
    /// Enable behavioral analysis
    pub enabled: bool,
    /// Minimum sessions for profile
    pub min_sessions_for_profile: u8,
    /// Confidence threshold for auto-unlock
    pub unlock_threshold: f32,
    /// Lock threshold
    pub lock_threshold: f32,
    /// Enable keystroke analysis
    pub keystroke_enabled: bool,
    /// Enable touch analysis (mobile)
    pub touch_enabled: bool,
    /// Enable mouse analysis (desktop)
    pub mouse_enabled: bool,
    /// Collect during password entry only
    pub password_entry_only: bool,
    /// Auto-lock timeout after suspicious behavior (seconds)
    pub auto_lock_timeout: u64,
}

impl Default for BehavioralSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            min_sessions_for_profile: 5,
            unlock_threshold: 0.6,
            lock_threshold: 0.3,
            keystroke_enabled: true,
            touch_enabled: true,
            mouse_enabled: true,
            password_entry_only: true,
            auto_lock_timeout: 60,
        }
    }
}

impl BehavioralSession {
    /// Create new session
    pub fn new(session_type: SessionType) -> Self {
        Self {
            id: Uuid::new_v4(),
            keystrokes: Vec::new(),
            touch_samples: Vec::new(),
            mouse_samples: Vec::new(),
            start_time: Utc::now(),
            end_time: None,
            session_type,
        }
    }

    /// Add keystroke sample
    pub fn add_keystroke(&mut self, key: char, press_time: u64, release_time: u64) {
        let inter_key_time = self.keystrokes.last()
            .map(|last| press_time - last.release_time);
        
        self.keystrokes.push(KeystrokeSample {
            key,
            press_time,
            release_time,
            inter_key_time,
        });
    }

    /// Add touch sample
    pub fn add_touch(&mut self, x: f32, y: f32, pressure: f32, timestamp: u64) {
        self.touch_samples.push(TouchSample {
            x,
            y,
            pressure,
            timestamp,
        });
    }

    /// Add mouse sample
    pub fn add_mouse(&mut self, x: f32, y: f32, velocity: f32, event_type: MouseEventType) {
        // Simplified - using timestamp from sample count
        let timestamp = self.mouse_samples.len() as u64 * 16; // ~60fps
        
        self.mouse_samples.push(MouseSample {
            x,
            y,
            velocity,
            event_type,
            timestamp,
        });
    }

    /// End session
    pub fn end_session(&mut self) {
        self.end_time = Some(Utc::now());
    }

    /// Duration in milliseconds
    pub fn duration_ms(&self) -> u64 {
        if let Some(end) = self.end_time {
            (end - self.start_time).num_milliseconds() as u64
        } else {
            (Utc::now() - self.start_time).num_milliseconds() as u64
        }
    }
}

/// Analyzer factory
pub fn create_analyzer(settings: &BehavioralSettings) -> BehavioralAnalyzer {
    BehavioralAnalyzer::new(settings.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = BehavioralSession::new(SessionType::PasswordEntry);
        
        assert!(!session.id.is_nil());
        assert!(session.keystrokes.is_empty());
    }

    #[test]
    fn test_keystroke_adding() {
        let mut session = BehavioralSession::new(SessionType::PasswordEntry);
        
        session.add_keystroke('a', 0, 50);
        assert_eq!(session.keystrokes.len(), 1);
        
        session.add_keystroke('b', 100, 150);
        assert_eq!(session.keystrokes.len(), 2);
        
        // Check inter-key time
        assert_eq!(session.keystrokes[1].inter_key_time, Some(50));
    }

    #[test]
    fn test_verification_result() {
        let result = VerificationResult::from_confidence(0.8);
        
        assert_eq!(result.threat_level, ThreatLevel::Low);
        assert_eq!(result.action, VerificationAction::Allow);
        
        let result2 = VerificationResult::from_confidence(0.3);
        
        assert_eq!(result2.threat_level, ThreatLevel::High);
        assert_eq!(result2.action, VerificationAction::LockVault);
    }

    #[test]
    fn test_session_duration() {
        let mut session = BehavioralSession::new(SessionType::PINEntry);
        
        // Short duration
        assert!(session.duration_ms() < 1000);
        
        session.end_session();
        
        assert!(session.end_time.is_some());
    }
}