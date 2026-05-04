//! Gesture Analysis Module

use super::{TouchSample, MouseSample, MouseEventType};

/// Gesture analyzer for touch and mouse patterns
pub struct GestureAnalyzer;

impl GestureAnalyzer {
    /// Analyze touch samples (mobile)
    pub fn analyze_touch(samples: &[TouchSample]) -> TouchProfile {
        if samples.is_empty() {
            return TouchProfile::default();
        }
        
        // Calculate pressure statistics
        let pressures: Vec<f32> = samples.iter().map(|s| s.pressure).collect();
        let avg_pressure = mean_f32(&pressures);
        let std_pressure = std_dev_f32(&pressures);
        
        // Calculate movement patterns
        let velocities: Vec<f32> = samples.windows(2)
            .map(|w| {
                let dx = w[1].x - w[0].x;
                let dy = w[1].y - w[0].y;
                let dt = (w[1].timestamp - w[0].timestamp) as f32;
                if dt > 0.0 {
                    (dx * dx + dy * dy).sqrt() / dt
                } else {
                    0.0
                }
            })
            .collect();
        
        let avg_velocity = mean_f32(&velocities);
        let std_velocity = std_dev_f32(&velocities);
        
        // Detect dominant direction
        let direction_bias = calculate_direction_bias(samples);
        
        // Gesture type classification
        let gesture_type = classify_touch_gesture(samples);
        
        TouchProfile {
            avg_pressure,
            std_pressure,
            avg_velocity,
            std_velocity,
            direction_bias,
            gesture_type,
            total_touches: samples.len() as u32,
        }
    }

    /// Analyze mouse samples (desktop)
    pub fn analyze_mouse(samples: &[MouseSample]) -> MouseProfile {
        if samples.is_empty() {
            return MouseProfile::default();
        }
        
        // Calculate velocity statistics
        let velocities: Vec<f32> = samples.iter().map(|s| s.velocity).collect();
        let avg_velocity = mean_f32(&velocities);
        let std_velocity = std_dev_f32(&velocities);
        
        // Count event types
        let click_count = samples.iter().filter(|s| s.event_type == MouseEventType::Click).count();
        let move_count = samples.iter().filter(|s| s.event_type == MouseEventType::Move).count();
        let scroll_count = samples.iter().filter(|s| s.event_type == MouseEventType::Scroll).count();
        
        // Movement pattern classification
        let movement_type = if std_velocity < 5.0 {
            MouseMovementType::Smooth
        } else if std_velocity < 15.0 {
            MouseMovementType::Normal
        } else {
            MouseMovementType::Jerky
        };
        
        MouseProfile {
            avg_velocity,
            std_velocity,
            click_count: click_count as u32,
            move_count: move_count as u32,
            scroll_count: scroll_count as u32,
            movement_type,
            total_events: samples.len() as u32,
        }
    }

    /// Compare touch samples to profile
    pub fn compare_touch(samples: &[TouchSample], profile: &TouchProfile) -> f32 {
        let current = Self::analyze_touch(samples);
        
        let pressure_diff = (current.avg_pressure - profile.avg_pressure).abs();
        let velocity_diff = (current.avg_velocity - profile.avg_velocity).abs();
        
        let pressure_score = (1.0 - (pressure_diff / 0.5).min(1.0));
        let velocity_score = (1.0 - (velocity_diff / 50.0).min(1.0));
        
        pressure_score * 0.5 + velocity_score * 0.5
    }

    /// Compare mouse samples to profile
    pub fn compare_mouse(samples: &[MouseSample], profile: &MouseProfile) -> f32 {
        let current = Self::analyze_mouse(samples);
        
        let velocity_diff = (current.avg_velocity - profile.avg_velocity).abs();
        
        (1.0 - (velocity_diff / 30.0).min(1.0))
    }
}

/// Touch profile
#[derive(Debug, Clone)]
pub struct TouchProfile {
    pub avg_pressure: f32,
    pub std_pressure: f32,
    pub avg_velocity: f32,
    pub std_velocity: f32,
    pub direction_bias: DirectionBias,
    pub gesture_type: TouchGestureType,
    pub total_touches: u32,
}

impl Default for TouchProfile {
    fn default() -> Self {
        Self {
            avg_pressure: 0.0,
            std_pressure: 0.0,
            avg_velocity: 0.0,
            std_velocity: 0.0,
            direction_bias: DirectionBias::None,
            gesture_type: TouchGestureType::Unknown,
            total_touches: 0,
        }
    }
}

/// Mouse profile
#[derive(Debug, Clone)]
pub struct MouseProfile {
    pub avg_velocity: f32,
    pub std_velocity: f32,
    pub click_count: u32,
    pub move_count: u32,
    pub scroll_count: u32,
    pub movement_type: MouseMovementType,
    pub total_events: u32,
}

impl Default for MouseProfile {
    fn default() -> Self {
        Self {
            avg_velocity: 0.0,
            std_velocity: 0.0,
            click_count: 0,
            move_count: 0,
            scroll_count: 0,
            movement_type: MouseMovementType::Unknown,
            total_events: 0,
        }
    }
}

/// Direction bias
#[derive(Debug, Clone)]
pub enum DirectionBias {
    None,
    Horizontal,
    Vertical,
    DiagonalUp,
    DiagonalDown,
}

/// Touch gesture type
#[derive(Debug, Clone)]
pub enum TouchGestureType {
    Tap,
    Swipe,
    Scroll,
    Pinch,
    Unknown,
}

/// Mouse movement type
#[derive(Debug, Clone)]
pub enum MouseMovementType {
    Smooth,
    Normal,
    Jerky,
    Unknown,
}

// Helper functions
fn mean_f32(data: &[f32]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().sum::<f32>() / data.len() as f32
}

fn std_dev_f32(data: &[f32]) -> f32 {
    if data.len() < 2 {
        return 0.0;
    }
    let avg = mean_f32(data);
    let variance = data.iter()
        .map(|x| (x - avg).powi(2))
        .sum::<f32>() / data.len() as f32;
    variance.sqrt()
}

fn calculate_direction_bias(samples: &[TouchSample]) -> DirectionBias {
    if samples.len() < 2 {
        return DirectionBias::None;
    }
    
    let mut horizontal = 0.0f32;
    let mut vertical = 0.0f32;
    
    for window in samples.windows(2) {
        horizontal += window[1].x - window[0].x;
        vertical += window[1].y - window[0].y;
    }
    
    if horizontal.abs() > vertical.abs() * 2.0 {
        DirectionBias::Horizontal
    } else if vertical.abs() > horizontal.abs() * 2.0 {
        DirectionBias::Vertical
    } else if horizontal > 0.0 && vertical > 0.0 {
        DirectionBias::DiagonalUp
    } else if horizontal > 0.0 && vertical < 0.0 {
        DirectionBias::DiagonalDown
    } else {
        DirectionBias::None
    }
}

fn classify_touch_gesture(samples: &[TouchSample]) -> TouchGestureType {
    if samples.len() == 1 {
        TouchGestureType::Tap
    } else if samples.len() < 5 {
        TouchGestureType::Tap
    } else {
        TouchGestureType::Swipe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_touch_analysis() {
        let samples = vec![
            TouchSample { x: 100.0, y: 100.0, pressure: 0.5, timestamp: 0 },
            TouchSample { x: 110.0, y: 100.0, pressure: 0.6, timestamp: 10 },
            TouchSample { x: 120.0, y: 100.0, pressure: 0.5, timestamp: 20 },
        ];
        
        let profile = GestureAnalyzer::analyze_touch(&samples);
        
        assert_eq!(profile.total_touches, 3);
    }

    #[test]
    fn test_mouse_analysis() {
        let samples = vec![
            MouseSample { x: 100.0, y: 100.0, velocity: 5.0, timestamp: 0, event_type: MouseEventType::Move },
            MouseSample { x: 150.0, y: 150.0, velocity: 10.0, timestamp: 16, event_type: MouseEventType::Move },
        ];
        
        let profile = GestureAnalyzer::analyze_mouse(&samples);
        
        assert_eq!(profile.total_events, 2);
    }

    #[test]
    fn test_compare() {
        let samples = vec![
            TouchSample { x: 100.0, y: 100.0, pressure: 0.5, timestamp: 0 },
        ];
        
        let profile = TouchProfile::default();
        let score = GestureAnalyzer::compare_touch(&samples, &profile);
        
        assert!(score >= 0.0 && score <= 1.0);
    }
}