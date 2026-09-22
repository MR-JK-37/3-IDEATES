use crate::llm::LLMEngine;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Threat Explainer using LLM for user-friendly explanations
pub struct ThreatExplainer {
    llm_engine: LLMEngine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatExplanation {
    pub threat_name: String,
    pub file_path: String,
    pub explanation: String,
    pub danger_level: DangerLevel,
    pub recommended_actions: Vec<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DangerLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatExplainer {
    pub fn new(llm_engine: LLMEngine) -> Self {
        Self { llm_engine }
    }

    /// Explain a detected threat in plain language
    pub async fn explain_threat(&self, threat_name: &str, file_path: &str) -> Result<String> {
        info!("Generating explanation for threat: {}", threat_name);

        let explanation = self
            .llm_engine
            .explain_threat_simple(threat_name, file_path)
            .await?;

        Ok(explanation)
    }

    /// Generate full threat report
    pub async fn generate_report(
        &self,
        threat_name: &str,
        file_path: &str,
    ) -> Result<ThreatExplanation> {
        let explanation = self.explain_threat(threat_name, file_path).await?;

        let danger_level = self.assess_danger_level(threat_name);

        let recommended_actions = self.get_recommendations(threat_name).await?;

        Ok(ThreatExplanation {
            threat_name: threat_name.to_string(),
            file_path: file_path.to_string(),
            explanation,
            danger_level,
            recommended_actions,
            timestamp: format!(
                "{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs()
            ),
        })
    }

    /// Assess danger level based on threat name
    fn assess_danger_level(&self, threat_name: &str) -> DangerLevel {
        let lower = threat_name.to_lowercase();

        if lower.contains("trojan") || lower.contains("ransomware") || lower.contains("worm") {
            DangerLevel::Critical
        } else if lower.contains("backdoor") || lower.contains("rootkit") {
            DangerLevel::High
        } else if lower.contains("pup") || lower.contains("adware") {
            DangerLevel::Medium
        } else {
            DangerLevel::Low
        }
    }

    /// Get recommended actions for a threat
    async fn get_recommendations(&self, threat_name: &str) -> Result<Vec<String>> {
        match threat_name.to_lowercase().as_str() {
            _ if threat_name.to_lowercase().contains("ransomware") => Ok(vec![
                "Do not pay the ransom".to_string(),
                "Disconnect infected computer from network".to_string(),
                "Boot into safe mode and run antivirus scan".to_string(),
                "Consider professional data recovery services".to_string(),
            ]),
            _ if threat_name.to_lowercase().contains("trojan") => Ok(vec![
                "Do not open the infected file".to_string(),
                "Quarantine immediately".to_string(),
                "Change all passwords from another computer".to_string(),
                "Monitor for identity theft".to_string(),
            ]),
            _ if threat_name.to_lowercase().contains("backdoor") => Ok(vec![
                "Isolate computer immediately".to_string(),
                "Contact IT security team".to_string(),
                "Run full system scan".to_string(),
                "Consider clean OS reinstall".to_string(),
            ]),
            _ => Ok(vec![
                "Quarantine the file".to_string(),
                "Run full antivirus scan".to_string(),
                "Keep system updated".to_string(),
            ]),
        }
    }
}
