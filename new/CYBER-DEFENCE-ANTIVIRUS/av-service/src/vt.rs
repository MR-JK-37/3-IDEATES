use anyhow::Context;
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug)]
pub struct VTResult {
    pub malicious_count: u64,
    pub harmless_count: u64,
    pub suspicious_count: u64,
    pub total_engines: u64,
    pub summary: String,
}

#[derive(Deserialize)]
struct VTResponseData {
    data: Option<serde_json::Value>,
}

pub async fn virustotal_check(hash: &str, api_key: &str) -> anyhow::Result<Option<VTResult>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);
    let res = client
        .get(&url)
        .header("x-apikey", api_key)
        .send()
        .await
        .context("vt request failed")?;

    if res.status().as_u16() == 404 {
        return Ok(None);
    }

    let json: serde_json::Value = res.json().await.context("vt parse json")?;

    // Navigate to attributes.last_analysis_stats
    let stats = json
        .get("data")
        .and_then(|d| d.get("attributes"))
        .and_then(|a| a.get("last_analysis_stats"));

    if let Some(s) = stats {
        let malicious = s.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0);
        let harmless = s.get("harmless").and_then(|v| v.as_u64()).unwrap_or(0);
        let suspicious = s.get("suspicious").and_then(|v| v.as_u64()).unwrap_or(0);
        let total = malicious + harmless + suspicious;
        let summary = format!("malicious={} harmless={} suspicious={}", malicious, harmless, suspicious);
        if malicious > 0 {
            return Ok(Some(VTResult {
                malicious_count: malicious,
                harmless_count: harmless,
                suspicious_count: suspicious,
                total_engines: total,
                summary,
            }));
        }
    }

    Ok(None)
}
