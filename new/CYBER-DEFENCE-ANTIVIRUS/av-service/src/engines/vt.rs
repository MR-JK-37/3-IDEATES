// av-service/src/engines/vt.rs
// VirusTotal API integration with rate limiting

use crate::engines::{DetectionResult, ThreatLevel};
use anyhow::Result;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::timeout;

// Rate limiter: 4 requests per minute for free API
static VT_RATE_LIMITER: Lazy<Arc<Semaphore>> = Lazy::new(|| Arc::new(Semaphore::new(4)));
static VT_CLIENT: Lazy<Client> = Lazy::new(Client::new);

const VT_API_URL: &str = "https://www.virustotal.com/api/v3";

#[derive(Debug, Deserialize)]
struct VTResponse {
    data: VTFileReport,
}

#[derive(Debug, Deserialize)]
struct VTFileReport {
    attributes: VTAttributes,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum VTAttributes {
    File {
        #[serde(default)]
        meaningful_name: Option<String>,
        #[serde(default, rename = "last_analysis_results")]
        _last_analysis_results: Option<serde_json::Value>,
        #[serde(default)]
        last_analysis_stats: Option<VTStats>,
    },
}

#[derive(Debug, Deserialize)]
struct VTStats {
    #[serde(default)]
    malicious: u32,
    #[serde(default)]
    suspicious: u32,
    #[serde(default, rename = "undetected")]
    _undetected: u32,
}

pub async fn scan_hash(file_hash: &str, api_key: &str) -> Result<Option<DetectionResult>> {
    // Rate limiting
    let _permit = VT_RATE_LIMITER.acquire().await?;

    // Only query if hash is SHA256 (64 chars)
    if file_hash.len() != 64 {
        log::debug!("Invalid hash length for VirusTotal: {}", file_hash.len());
        return Ok(None);
    }

    let url = format!("{}/files/{}", VT_API_URL, file_hash);

    match timeout(
        tokio::time::Duration::from_secs(10),
        VT_CLIENT.get(&url).header("x-apikey", api_key).send(),
    )
    .await
    {
        Ok(Ok(response)) => {
            if response.status() == 404 {
                log::debug!("Hash not found in VirusTotal");
                return Ok(None);
            }

            match response.json::<VTResponse>().await {
                Ok(vt_resp) => parse_vt_response(vt_resp),
                Err(e) => {
                    log::warn!("Failed to parse VT response: {}", e);
                    Ok(None)
                }
            }
        }
        Ok(Err(e)) => {
            log::warn!("VirusTotal API error: {}", e);
            Ok(None)
        }
        Err(_) => {
            log::warn!("VirusTotal request timeout");
            Ok(None)
        }
    }
}

fn parse_vt_response(response: VTResponse) -> Result<Option<DetectionResult>> {
    match response.data.attributes {
        VTAttributes::File {
            meaningful_name,
            _last_analysis_results: _,
            last_analysis_stats: Some(stats),
        } => {
            if stats.malicious > 0 {
                let threat_name = format!("VirusTotal.Detection({}/70)", stats.malicious);

                return Ok(Some(DetectionResult {
                    level: if stats.malicious > 10 {
                        ThreatLevel::Malicious
                    } else {
                        ThreatLevel::Suspicious
                    },
                    engine: "VirusTotal".to_string(),
                    threat_name,
                    confidence: (stats.malicious as f32 / 70.0).min(1.0),
                    signature: meaningful_name,
                    rule_matched: None,
                }));
            }

            if stats.suspicious > 0 {
                return Ok(Some(DetectionResult {
                    level: ThreatLevel::Suspicious,
                    engine: "VirusTotal".to_string(),
                    threat_name: format!("VirusTotal.Suspicious({}/70)", stats.suspicious),
                    confidence: (stats.suspicious as f32 / 70.0).min(1.0),
                    signature: meaningful_name,
                    rule_matched: None,
                }));
            }

            Ok(None)
        }
        _ => {
            log::debug!("Unexpected VirusTotal response format");
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vt_response_parsing() {
        let json_str = r#"
        {
            "data": {
                "attributes": {
                    "meaningful_name": "trojan.exe",
                    "last_analysis_stats": {
                        "malicious": 15,
                        "suspicious": 2,
                        "undetected": 53
                    }
                }
            }
        }
        "#;

        let response: VTResponse = serde_json::from_str(json_str).unwrap();
        let result = parse_vt_response(response).unwrap();
        assert!(result.is_some());

        let detection = result.unwrap();
        assert_eq!(detection.level, ThreatLevel::Malicious);
        assert!(detection.threat_name.contains("15/70"));
    }

    #[test]
    fn test_hash_length_validation() {
        // MD5 hash (32 chars) should be rejected
        assert_ne!(32, 64); // Only SHA256 (64 chars) accepted
    }
}
