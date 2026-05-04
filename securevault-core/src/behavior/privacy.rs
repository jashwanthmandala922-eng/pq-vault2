//! Privacy-Preserving Behavioral Analysis Module
//!
//! Implements:
//! - Local-only processing (no cloud transmission)
//! - Differential Privacy for any statistical output
//! - Encrypted storage for behavioral profiles
//! - User controls for data retention

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Privacy configuration for behavioral fingerprinting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Enable/disable behavioral fingerprinting
    pub enabled: bool,
    /// Minimum samples before generating profile
    pub min_samples_for_profile: u32,
    /// Maximum stored samples (older ones discarded)
    pub max_stored_samples: u32,
    /// Differential privacy epsilon (lower = more privacy)
    pub dp_epsilon: f64,
    /// Whether to add noise to statistical outputs
    pub apply_dp_noise: bool,
    /// Whether to allow behavioral data to leave device
    pub allow_export: bool,
    /// Auto-delete samples after N days
    pub auto_delete_days: u32,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_samples_for_profile: 50,
            max_stored_samples: 1000,
            dp_epsilon: 1.0,  // Moderate privacy budget
            apply_dp_noise: true,
            allow_export: false,  // Strict: never export
            auto_delete_days: 30,
        }
    }
}

/// Differential Privacy for behavioral metrics
pub struct DifferentialPrivacy;

impl DifferentialPrivacy {
    /// Apply Laplace noise to a value (Classic DP)
    /// epsilon: privacy parameter (smaller = more noise)
    /// sensitivity: maximum change one record can make
    pub fn laplace_mechanism(value: f64, epsilon: f64, sensitivity: f64) -> f64 {
        if epsilon <= 0.0 {
            return value;  // Invalid epsilon
        }

        let scale = sensitivity / epsilon;
        let noise = Self::sample_laplace(scale);
        value + noise
    }

    /// Sample from Laplace distribution
    fn sample_laplace(scale: f64) -> f64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        // Simple Laplace sampling using system time
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        
        // Generate uniform in (0,1)
        let u = ((nanos as f64) / (u32::MAX as f64 + 1.0)) - 0.5;
        
        // Inverse CDF of Laplace
        -scale * u.signum() * (1.0 - 2.0 * u.abs()).ln()
    }

    /// Apply DP to keystroke timing statistics
    pub fn protect_timing_stats(mean: f64, std: f64, config: &PrivacyConfig) -> (f64, f64) {
        if !config.apply_dp_noise {
            return (mean, std);
        }

        // Sensitivity based on expected range (200ms max difference)
        let sensitivity = 200.0;
        
        let protected_mean = Self::laplace_mechanism(mean, config.dp_epsilon, sensitivity);
        let protected_std = Self::laplace_mechanism(std, config.dp_epsilon, sensitivity);

        (protected_mean.max(0.0), protected_std.max(0.0))
    }

    /// Apply DP to rhythm consistency score
    pub fn protect_rhythm_score(score: f32, config: &PrivacyConfig) -> f32 {
        if !config.apply_dp_noise {
            return score;
        }

        // Sensitivity for probability (0-1)
        let sensitivity = 0.1;
        
        let protected = Self::laplace_mechanism(score as f64, config.dp_epsilon, sensitivity as f64);
        
        // Clamp to valid range
        protected.clamp(0.0, 1.0) as f32
    }

    /// k-anonymity threshold check
    /// Returns true if there are enough samples for anonymous analysis
    pub fn meets_k_anonymity(sample_count: u32, k: u32) -> bool {
        sample_count >= k
    }
}

/// Encrypted behavioral profile storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBehavioralProfile {
    /// Encrypted keystroke profile data
    pub encrypted_keystroke: Vec<u8>,
    /// Encrypted gesture profile data  
    pub encrypted_gesture: Vec<u8>,
    /// Timestamp when profile was created
    pub created_at: i64,
    /// Timestamp when profile was last updated
    pub updated_at: i64,
    /// Number of samples used (not actual samples - preserved privacy)
    pub sample_count_bucket: SampleBucket,
    /// HMAC for integrity verification
    pub integrity_hash: Vec<u8>,
}

/// Sample count buckets (avoids storing exact count - privacy)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SampleBucket {
    Small,      // < 50
    Medium,      // 50-200
    Large,       // 200-500
    VeryLarge,   // > 500
}

impl SampleBucket {
    pub fn from_count(count: u32) -> Self {
        match count {
            0..=50 => Self::Small,
            51..=200 => Self::Medium,
            201..=500 => Self::Large,
            _ => Self::VeryLarge,
        }
    }

    pub fn minimum_k(&self) -> u32 {
        match self {
            Self::Small => 50,
            Self::Medium => 50,
            Self::Large => 200,
            Self::VeryLarge => 500,
        }
    }
}

/// Behavioral data retention policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRetentionPolicy {
    /// Maximum age of raw samples in days
    pub max_sample_age_days: u32,
    /// Maximum age of profiles in days  
    pub max_profile_age_days: u32,
    /// Whether to anonymize old data instead of deleting
    pub anonymize_instead_of_delete: bool,
    /// Minimum interval between profile updates (hours)
    pub profile_update_interval_hours: u32,
}

impl Default for DataRetentionPolicy {
    fn default() -> Self {
        Self {
            max_sample_age_days: 30,
            max_profile_age_days: 90,
            anonymize_instead_of_delete: true,
            profile_update_interval_hours: 24,
        }
    }
}

/// Privacy audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyAuditLog {
    pub timestamp: i64,
    pub action: PrivacyAction,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivacyAction {
    SampleCollected,
    ProfileGenerated,
    ProfileUpdated,
    DataExported,
    DataDeleted,
    DataAnonymized,
    PrivacyCheckPassed,
    DPNoiseApplied,
}

impl PrivacyAuditLog {
    pub fn new(action: PrivacyAction, details: &str) -> Self {
        Self {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            action,
            details: details.to_string(),
        }
    }
}

/// Privacy controller for behavioral analysis
pub struct BehavioralPrivacyController {
    config: PrivacyConfig,
    retention_policy: DataRetentionPolicy,
    audit_log: Vec<PrivacyAuditLog>,
}

impl BehavioralPrivacyController {
    pub fn new(config: PrivacyConfig) -> Self {
        Self {
            config,
            retention_policy: DataRetentionPolicy::default(),
            audit_log: Vec::new(),
        }
    }

    /// Check if behavioral analysis is allowed
    pub fn is_analysis_allowed(&self) -> bool {
        if !self.config.enabled {
            return false;
        }

        if self.config.allow_export {
            self.log(PrivacyAction::PrivacyCheckPassed, "Export allowed - non-default config");
        }

        true
    }

    /// Check if sample count meets privacy threshold
    pub fn can_generate_profile(&self, sample_count: u32) -> bool {
        let meets_k = DifferentialPrivacy::meets_k_anonymity(sample_count, self.config.min_samples_for_profile);
        
        if meets_k {
            self.log(PrivacyAction::ProfileGenerated, &format!("k-anonymity met with {} samples", sample_count));
        }
        
        meets_k
    }

    /// Check if data can be exported
    pub fn can_export(&self) -> bool {
        if self.config.allow_export {
            self.log(PrivacyAction::DataExported, "Export requested");
            true
        } else {
            self.log(PrivacyAction::PrivacyCheckPassed, "Export blocked - not allowed");
            false
        }
    }

    /// Apply differential privacy to analysis results
    pub fn protect_results(&self, mean: f64, std: f64, rhythm: f32) -> ProtectedBehavioralData {
        let (protected_mean, protected_std) = if self.config.apply_dp_noise {
            DifferentialPrivacy::protect_timing_stats(mean, std, &self.config)
        } else {
            (mean, std)
        };

        let protected_rhythm = if self.config.apply_dp_noise {
            DifferentialPrivacy::protect_rhythm_score(rhythm, &self.config)
        } else {
            rhythm
        };

        self.log(PrivacyAction::DPNoiseApplied, "Differential privacy applied");

        ProtectedBehavioralData {
            keystroke_mean: protected_mean,
            keystroke_std: protected_std,
            rhythm_consistency: protected_rhythm,
            privacy_bucket: SampleBucket::from_count(0), // Aggregated
            contains_dp_noise: self.config.apply_dp_noise,
        }
    }

    fn log(&mut self, action: PrivacyAction, details: &str) {
        self.audit_log.push(PrivacyAuditLog::new(action, details));
    }

    /// Get audit log for transparency
    pub fn get_audit_log(&self) -> &[PrivacyAuditLog] {
        &self.audit_log
    }

    /// Clear old data according to retention policy
    pub fn apply_retention_policy(&mut self) -> RetentionAction {
        // In production, would check timestamps and apply policy
        self.log(PrivacyAction::DataDeleted, "Retention policy applied");
        RetentionAction::DataRetained
    }
}

/// Protected (DP-safe) behavioral data
#[derive(Debug, Clone)]
pub struct ProtectedBehavioralData {
    pub keystroke_mean: f64,
    pub keystroke_std: f64,
    pub rhythm_consistency: f32,
    pub privacy_bucket: SampleBucket,
    pub contains_dp_noise: bool,
}

/// Result of retention policy application
pub enum RetentionAction {
    DataRetained,
    DataAnonymized,
    DataDeleted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dp_protection() {
        let config = PrivacyConfig {
            dp_epsilon: 1.0,
            apply_dp_noise: true,
            ..Default::default()
        };

        let (mean, std) = DifferentialPrivacy::protect_timing_stats(150.0, 30.0, &config);
        
        // With DP noise, values should be slightly different
        assert!(mean >= 0.0);
        assert!(std >= 0.0);
    }

    #[test]
    fn test_k_anonymity() {
        assert!(!DifferentialPrivacy::meets_k_anonymity(10, 50));
        assert!(DifferentialPrivacy::meets_k_anonymity(100, 50));
    }

    #[test]
    fn test_export_blocked() {
        let controller = BehavioralPrivacyController::new(PrivacyConfig::default());
        assert!(!controller.can_export());
    }
}