//! Behavioral Analyzer Module
//!
//! Coordinates all behavioral analysis components

use super::{
    BehavioralSession, BehavioralProfile, BehavioralSettings,
    VerificationResult, VerificationAction, ThreatLevel,
    KeystrokeAnalyzer, GestureAnalyzer,
};

/// Main behavioral analyzer
pub struct BehavioralAnalyzer {
    settings: BehavioralSettings,
    profile: BehavioralProfile,
    current_session: Option<BehavioralSession>,
}

impl BehavioralAnalyzer {
    /// Create new analyzer
    pub fn new(settings: BehavioralSettings) -> Self {
        Self {
            settings,
            profile: BehavioralProfile::new(),
            current_session: None,
        }
    }

    /// Start a new session
    pub fn start_session(&mut self, session_type: super::SessionType) {
        self.current_session = Some(BehavioralSession::new(session_type));
    }

    /// Add keystroke to current session
    pub fn add_keystroke(&mut self, key: char, press_time: u64, release_time: u64) {
        if let Some(ref mut session) = self.current_session {
            session.add_keystroke(key, press_time, release_time);
        }
    }

    /// Add touch to current session
    pub fn add_touch(&mut self, x: f32, y: f32, pressure: f32, timestamp: u64) {
        if let Some(ref mut session) = self.current_session {
            session.add_touch(x, y, pressure, timestamp);
        }
    }

    /// Add mouse event to current session
    pub fn add_mouse(&mut self, x: f32, y: f32, velocity: f32, event_type: super::MouseEventType) {
        if let Some(ref mut session) = self.current_session {
            session.add_mouse(x, y, velocity, event_type);
        }
    }

    /// End current session and verify
    pub fn end_session(&mut self) -> VerificationResult {
        if let Some(mut session) = self.current_session.take() {
            session.end_session();
            
            // Update profile with session data
            if self.settings.enabled {
                self.profile.update(&session);
            }
            
            // Verify if profile is ready
            if self.profile.ready {
                let confidence = self.profile.verify(&session);
                VerificationResult::from_confidence(confidence)
            } else {
                // Not enough data - allow but warn
                VerificationResult {
                    confidence: 0.5,
                    threat_level: ThreatLevel::Low,
                    action: VerificationAction::Allow,
                    details: "Profile not ready - allow with warning".to_string(),
                }
            }
        } else {
            // No session - allow
            VerificationResult::from_confidence(0.8)
        }
    }

    /// Verify without ending session (for real-time)
    pub fn verify_current(&self) -> VerificationResult {
        if let Some(ref session) = self.current_session {
            if self.profile.ready {
                let confidence = self.profile.verify(session);
                VerificationResult::from_confidence(confidence)
            } else {
                VerificationResult::from_confidence(0.5)
            }
        } else {
            VerificationResult::from_confidence(0.8)
        }
    }

    /// Get current profile
    pub fn profile(&self) -> &BehavioralProfile {
        &self.profile
    }

    /// Check if ready for verification
    pub fn is_ready(&self) -> bool {
        self.profile.ready
    }

    /// Anomaly detection
    pub fn detect_anomalies(&self) -> Vec<super::keystroke::Anomaly> {
        if let Some(ref session) = self.current_session {
            if let Some(ref profile) = self.profile.keystroke {
                KeystrokeAnalyzer::detect_anomalies(&session.keystrokes, profile)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    }

    /// Clear current session without saving
    pub fn cancel_session(&mut self) {
        self.current_session = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let settings = BehavioralSettings::default();
        let analyzer = BehavioralAnalyzer::new(settings);
        
        assert!(!analyzer.is_ready());
    }

    #[test]
    fn test_session_flow() {
        let mut analyzer = BehavioralAnalyzer::new(BehavioralSettings::default());
        
        // Start session
        analyzer.start_session(super::SessionType::PasswordEntry);
        
        // Add keystrokes
        analyzer.add_keystroke('p', 0, 50);
        analyzer.add_keystroke('a', 100, 150);
        
        // End session
        let result = analyzer.end_session();
        
        assert!(result.confidence >= 0.0);
    }

    #[test]
    fn test_verify_current() {
        let mut analyzer = BehavioralAnalyzer::new(BehavioralSettings::default());
        
        analyzer.start_session(super::SessionType::GeneralTyping);
        analyzer.add_keystroke('t', 0, 50);
        
        let result = analyzer.verify_current();
        
        assert!(result.confidence >= 0.0);
    }

    #[test]
    fn test_cancel_session() {
        let mut analyzer = BehavioralAnalyzer::new(BehavioralSettings::default());
        
        analyzer.start_session(super::SessionType::PINEntry);
        analyzer.add_keystroke('1', 0, 50);
        analyzer.cancel_session();
        
        // After cancel, should not have current session
        let result = analyzer.verify_current();
        
        // Should be neutral or allow
        assert!(result.action == VerificationAction::Allow);
    }

    #[test]
    fn test_profile() {
        let analyzer = BehavioralAnalyzer::new(BehavioralSettings::default());
        
        let profile = analyzer.profile();
        
        assert!(!profile.id.is_empty());
    }
}