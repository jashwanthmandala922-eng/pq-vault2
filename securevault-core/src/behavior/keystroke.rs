//! Keystroke Analysis Module

use super::{KeystrokeSample, SessionType};

/// Keystroke analyzer
pub struct KeystrokeAnalyzer;

impl KeystrokeAnalyzer {
    /// Analyze keystroke samples and return typing pattern
    pub fn analyze(samples: &[KeystrokeSample]) -> KeystrokeProfile {
        if samples.is_empty() {
            return KeystrokeProfile::default();
        }
        
        // Calculate timing statistics
        let press_durations: Vec<u64> = samples.iter()
            .map(|s| s.release_time - s.press_time)
            .collect();
        
        let inter_key_times: Vec<u64> = samples.iter()
            .filter_map(|s| s.inter_key_time)
            .collect();
        
        // Calculate mean and std dev
        let avg_press = mean(&press_durations);
        let std_press = std_dev(&press_durations);
        
        let avg_inter = if inter_key_times.is_empty() {
            0.0
        } else {
            mean(&inter_key_times)
        };
        
        let std_inter = if inter_key_times.is_empty() {
            0.0
        } else {
            std_dev(&inter_key_times)
        };
        
        // Determine typing style
        let typing_style = if std_inter < 30.0 {
            TypingStyle::HuntAndPeck
        } else if std_inter < 80.0 {
            TypingStyle::TouchTypist
        } else {
            TypingStyle::Hybrid
        };
        
        // Calculate rhythm consistency
        let rhythm_score = if inter_key_times.len() > 2 {
            1.0 - (std_inter / (avg_inter + 1.0)).min(1.0)
        } else {
            0.5
        };
        
        KeystrokeProfile {
            avg_press_duration: avg_press,
            std_press_duration: std_press,
            avg_inter_key_time: avg_inter,
            std_inter_key_time: std_inter,
            typing_style,
            rhythm_consistency: rhythm_score,
            total_keys: samples.len() as u32,
        }
    }

    /// Compare current samples to profile
    pub fn compare(samples: &[KeystrokeSample], profile: &KeystrokeProfile) -> f32 {
        let current = Self::analyze(samples);
        
        // Calculate similarity scores
        let press_diff = (current.avg_press_duration - profile.avg_press_duration).abs();
        let inter_diff = (current.avg_inter_key_time - profile.avg_inter_key_time).abs();
        
        // Normalize to 0-1
        let press_score = (1.0 - (press_diff / 200.0).min(1.0));
        let inter_score = (1.0 - (inter_diff / 200.0).min(1.0));
        
        // Weight by rhythm consistency
        let rhythm_weight = profile.rhythm_consistency;
        
        (press_score * 0.3 + inter_score * 0.5 + rhythm_weight * 0.2).min(1.0)
    }

    /// Detect anomalies
    pub fn detect_anomalies(samples: &[KeystrokeSample], profile: &KeystrokeProfile) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();
        
        let current = Self::analyze(samples);
        
        // Check press duration anomalies
        if (current.avg_press_duration - profile.avg_press_duration).abs() > 100.0 {
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::PressDuration,
                severity: Severity::Medium,
                description: "Press duration significantly different".to_string(),
            });
        }
        
        // Check inter-key time anomalies
        if (current.avg_inter_key_time - profile.avg_inter_key_time).abs() > 150.0 {
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::InterKeyTiming,
                severity: Severity::Medium,
                description: "Typing rhythm significantly different".to_string(),
            });
        }
        
        // Check typing style change
        if current.typing_style != profile.typing_style {
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::TypingStyle,
                severity: Severity::High,
                description: "Typing style changed".to_string(),
            });
        }
        
        anomalies
    }
}

/// Keystroke profile
#[derive(Debug, Clone)]
pub struct KeystrokeProfile {
    pub avg_press_duration: f64,
    pub std_press_duration: f64,
    pub avg_inter_key_time: f64,
    pub std_inter_key_time: f64,
    pub typing_style: TypingStyle,
    pub rhythm_consistency: f32,
    pub total_keys: u32,
}

impl Default for KeystrokeProfile {
    fn default() -> Self {
        Self {
            avg_press_duration: 0.0,
            std_press_duration: 0.0,
            avg_inter_key_time: 0.0,
            std_inter_key_time: 0.0,
            typing_style: TypingStyle::Unknown,
            rhythm_consistency: 0.0,
            total_keys: 0,
        }
    }
}

/// Typing style
#[derive(Debug, Clone, PartialEq)]
pub enum TypingStyle {
    HuntAndPeck,
    TouchTypist,
    Hybrid,
    Unknown,
}

/// Anomaly
#[derive(Debug, Clone)]
pub struct Anomaly {
    pub anomaly_type: AnomalyType,
    pub severity: Severity,
    pub description: String,
}

/// Anomaly type
#[derive(Debug, Clone)]
pub enum AnomalyType {
    PressDuration,
    InterKeyTiming,
    TypingStyle,
    TooFewKeys,
    TooFast,
    TooSlow,
}

/// Severity
#[derive(Debug, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
}

// Helper functions
fn mean(data: &[u64]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().sum::<u64>() as f64 / data.len() as f64
}

fn std_dev(data: &[u64]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }
    
    let avg = mean(data);
    let variance = data.iter()
        .map(|x| (*x as f64 - avg).powi(2))
        .sum::<f64>() / data.len() as f64;
    
    variance.sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_empty() {
        let profile = KeystrokeAnalyzer::analyze(&[]);
        
        assert_eq!(profile.total_keys, 0);
    }

    #[test]
    fn test_analyze_samples() {
        let samples = vec![
            KeystrokeSample { key: 'a', press_time: 0, release_time: 50, inter_key_time: None },
            KeystrokeSample { key: 'b', press_time: 100, release_time: 150, inter_key_time: Some(50) },
            KeystrokeSample { key: 'c', press_time: 200, release_time: 250, inter_key_time: Some(50) },
        ];
        
        let profile = KeystrokeAnalyzer::analyze(&samples);
        
        assert_eq!(profile.total_keys, 3);
        assert!(profile.avg_press_duration > 0.0);
    }

    #[test]
    fn test_compare() {
        // This test would need profile from previous samples
        // Simplified test
        let samples = vec![
            KeystrokeSample { key: 'a', press_time: 0, release_time: 50, inter_key_time: None },
        ];
        
        let profile = KeystrokeProfile::default();
        let score = KeystrokeAnalyzer::compare(&samples, &profile);
        
        assert!(score >= 0.0 && score <= 1.0);
    }
}