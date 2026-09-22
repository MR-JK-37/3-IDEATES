use serde::{Deserialize, Serialize};
use tracing::info;

/// Behavior analyzer for interpreting sandbox observations
#[derive(Debug)]
pub struct BehaviorAnalyzer {
    threat_threshold: f32,
}

impl BehaviorAnalyzer {
    pub fn new() -> Self {
        info!("Initializing Behavior Analyzer...");
        Self {
            threat_threshold: 0.6,
        }
    }

    /// Analyze file behavior and return threat assessment
    pub fn analyze(&self, behavior: &FileBehavior) -> ThreatAssessment {
        let mut score: f32 = 0.0;
        let mut indicators = vec![];

        // Ransomware indicators
        if behavior.mass_file_encryption {
            score += 0.4;
            indicators.push("Mass file encryption detected".to_string());
        }

        if behavior
            .suspicious_api_calls
            .contains(&"CryptEncrypt".to_string())
        {
            score += 0.2;
            indicators.push("Cryptographic API usage".to_string());
        }

        // Persistence indicators
        if behavior.registry_modifications {
            score += 0.15;
            indicators.push("Registry modifications".to_string());
        }

        if behavior.scheduled_tasks_created {
            score += 0.1;
            indicators.push("Scheduled task creation".to_string());
        }

        // Exfiltration indicators
        if behavior.network_connections > 5 {
            score += 0.15;
            indicators.push(format!(
                "{} network connections",
                behavior.network_connections
            ));
        }

        // Privilege escalation
        if behavior.privileges_elevated {
            score += 0.1;
            indicators.push("Privilege elevation attempt".to_string());
        }

        let threat_level = match score {
            s if s < 0.3 => ThreatLevel::Low,
            s if s < 0.6 => ThreatLevel::Medium,
            s if s < 0.8 => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        };

        ThreatAssessment {
            threat_score: score.min(1.0),
            threat_level,
            indicators,
            recommended_action: self.recommend_action(score),
        }
    }

    fn recommend_action(&self, score: f32) -> RecommendedAction {
        match score {
            s if s < 0.3 => RecommendedAction::Allow,
            s if s < 0.6 => RecommendedAction::Monitor,
            s if s < 0.8 => RecommendedAction::Block,
            _ => RecommendedAction::Quarantine,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBehavior {
    pub mass_file_encryption: bool,
    pub registry_modifications: bool,
    pub scheduled_tasks_created: bool,
    pub privileges_elevated: bool,
    pub network_connections: usize,
    pub suspicious_api_calls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAssessment {
    pub threat_score: f32,
    pub threat_level: ThreatLevel,
    pub indicators: Vec<String>,
    pub recommended_action: RecommendedAction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecommendedAction {
    Allow,
    Monitor,
    Block,
    Quarantine,
}

impl Default for BehaviorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_analysis() {
        let analyzer = BehaviorAnalyzer::new();

        let behavior = FileBehavior {
            mass_file_encryption: true,
            registry_modifications: true,
            scheduled_tasks_created: true,
            privileges_elevated: true,
            network_connections: 10,
            suspicious_api_calls: vec!["CryptEncrypt".to_string()],
        };

        let assessment = analyzer.analyze(&behavior);
        assert!(assessment.threat_score > 0.5);
        // With multiple high-severity indicators the analyzer should classify as Critical
        assert_eq!(assessment.threat_level, ThreatLevel::Critical);
    }
}
