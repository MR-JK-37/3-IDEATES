// av-service/src/engines/mod.rs
// Multi-engine detection system with ClamAV, YARA, VirusTotal, and heuristics

pub mod clamav;
pub mod heuristics;
pub mod ml;
pub mod signatures;
pub mod vt;
pub mod yara;

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatLevel {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub level: ThreatLevel,
    pub engine: String,
    pub threat_name: String,
    pub confidence: f32, // 0.0-1.0
    pub signature: Option<String>,
    pub rule_matched: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiEngineResult {
    pub file_path: String,
    pub file_hash: String,
    pub file_size: u64,
    pub entropy: f64,
    pub detections: Vec<DetectionResult>,
    pub final_verdict: ThreatLevel,
    pub scan_time_ms: u128,
}

pub async fn scan_with_all_engines(
    path: &Path,
    file_hash: &str,
    vt_key: Option<&str>,
    yara_rules: Option<&str>,
) -> anyhow::Result<MultiEngineResult> {
    let start = std::time::Instant::now();
    let mut detections = Vec::new();

    let file_size = std::fs::metadata(path)?.len();

    // 1. Check local hash database (fastest) - uses global init_db pool
    if let Ok(Some(cached_name)) = crate::hashdb::check_hash(file_hash) {
        detections.push(DetectionResult {
            level: ThreatLevel::Malicious,
            engine: "HashDB".to_string(),
            threat_name: cached_name,
            confidence: 1.0,
            signature: Some(file_hash.to_string()),
            rule_matched: None,
        });
    }

    // 2. High-confidence local signatures.
    if let Ok(Some(sig_result)) = signatures::scan(path).await {
        detections.push(sig_result);
    }

    // 3. Run heuristic analysis - only add non-Clean results
    if let Ok(heur_result) = heuristics::analyze_file(path).await {
        if heur_result.level != ThreatLevel::Clean {
            detections.push(heur_result);
        }
    }

    // 4. Run local trainable AI risk model.
    if let Ok(Some(ml_result)) = ml::score_file(path).await {
        detections.push(ml_result);
    }

    // 5. Run ClamAV if available
    if let Ok(Some(clam_result)) = clamav::scan(path).await {
        detections.push(clam_result);
    }

    // 6. Run YARA rules (explicit path or built-in defaults).
    let rules_path = yara_rules.unwrap_or("config/yara/default_rules.yar");
    if let Ok(Some(yara_result)) = yara::scan(path, rules_path).await {
        detections.push(yara_result);
    }

    // 7. Query VirusTotal if API key provided (rate-limited)
    if let Some(key) = vt_key {
        if let Ok(Some(vt_result)) = vt::scan_hash(file_hash, key).await {
            detections.push(vt_result);
        }
    }

    let final_verdict = finalize_verdict(&detections);

    // Cache malicious files in hash database
    if final_verdict == ThreatLevel::Malicious {
        let authoritative = detections.iter().find(|d| {
            d.level == ThreatLevel::Malicious
                && matches!(
                    d.engine.as_str(),
                    "HashDB" | "LocalSignatures" | "ClamAV" | "YARA" | "VirusTotal"
                )
        });
        if let Some(d) = authoritative {
            let _ = crate::hashdb::add_hash(file_hash, &d.threat_name, "MultiEngine");
        }
    }

    Ok(MultiEngineResult {
        file_path: path.display().to_string(),
        file_hash: file_hash.to_string(),
        file_size,
        entropy: heuristics::calculate_entropy_from_path(path).unwrap_or(0.0),
        detections,
        final_verdict,
        scan_time_ms: start.elapsed().as_millis(),
    })
}

fn finalize_verdict(detections: &[DetectionResult]) -> ThreatLevel {
    let has_authoritative_malicious = detections.iter().any(|d| {
        d.level == ThreatLevel::Malicious
            && matches!(
                d.engine.as_str(),
                "HashDB" | "LocalSignatures" | "ClamAV" | "YARA" | "VirusTotal"
            )
    });
    if has_authoritative_malicious {
        return ThreatLevel::Malicious;
    }

    // ML/heuristic-only "malicious" should not auto-promote without corroboration.
    let has_ml_malicious = detections
        .iter()
        .any(|d| d.level == ThreatLevel::Malicious && d.engine == "AI-RiskModel");
    if has_ml_malicious {
        let corroborated = detections.iter().any(|d| {
            d.engine != "AI-RiskModel" && d.engine != "Heuristic" && d.level != ThreatLevel::Clean
        });
        if corroborated {
            return ThreatLevel::Suspicious;
        }
    }

    let suspicious = detections
        .iter()
        .filter(|d| d.level == ThreatLevel::Suspicious)
        .collect::<Vec<_>>();

    if suspicious.is_empty() {
        return ThreatLevel::Clean;
    }

    let high_conf_non_heuristic = suspicious
        .iter()
        .any(|d| d.confidence >= 0.90 && d.engine != "Heuristic");

    if high_conf_non_heuristic || suspicious.len() >= 2 {
        ThreatLevel::Suspicious
    } else {
        ThreatLevel::Clean
    }
}
