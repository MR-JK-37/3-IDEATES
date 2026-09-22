// av-service/src/engines/yara.rs
// YARA rule-based detection engine

use crate::engines::{DetectionResult, ThreatLevel};
use anyhow::Result;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicI8, Ordering};
use tokio::process::Command;
use tokio::time::{timeout, Duration};

static YARA_AVAILABLE: AtomicI8 = AtomicI8::new(-1); // -1 unknown, 0 no, 1 yes

pub async fn scan(path: &Path, rules_path: &str) -> Result<Option<DetectionResult>> {
    if !Path::new(rules_path).exists() {
        return Ok(None);
    }

    // Check if yara is available
    if !is_yara_available().await {
        log::debug!("YARA not available, skipping");
        return Ok(None);
    }

    // Run yara with rules and timeout
    let output = timeout(
        Duration::from_secs(15),
        Command::new("yara")
            .arg("-r")
            .arg(rules_path)
            .arg(path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output(),
    )
    .await;

    match output {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_yara_output(&stdout)
        }
        Ok(Err(e)) => {
            log::warn!("YARA execution error: {}", e);
            Ok(None)
        }
        Err(_) => {
            log::warn!("YARA scan timeout");
            Ok(None)
        }
    }
}

fn parse_yara_output(output: &str) -> Result<Option<DetectionResult>> {
    // YARA output format: "rule_name /path/to/file"
    // If no matches, output is empty

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let rule_name = parts[0].to_string();

        // Categorize threat level based on rule name
        let (level, threat_name) = categorize_rule(&rule_name);

        return Ok(Some(DetectionResult {
            level,
            engine: "YARA".to_string(),
            threat_name,
            confidence: 0.85,
            signature: None,
            rule_matched: Some(rule_name),
        }));
    }

    Ok(None)
}

fn categorize_rule(rule_name: &str) -> (ThreatLevel, String) {
    let lower = rule_name.to_lowercase();

    // Malicious patterns
    if lower.contains("trojan")
        || lower.contains("malware")
        || lower.contains("ransomware")
        || lower.contains("backdoor")
        || lower.contains("worm")
        || lower.contains("virus")
    {
        return (ThreatLevel::Malicious, rule_name.to_string());
    }

    // Suspicious patterns
    if lower.contains("pup")
        || lower.contains("adware")
        || lower.contains("suspicious")
        || lower.contains("obfuscated")
    {
        return (ThreatLevel::Suspicious, rule_name.to_string());
    }

    // Default to malicious for unknown YARA matches
    (ThreatLevel::Malicious, rule_name.to_string())
}

async fn is_yara_available() -> bool {
    match YARA_AVAILABLE.load(Ordering::Relaxed) {
        0 => return false,
        1 => return true,
        _ => {}
    }

    match Command::new("yara")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
    {
        Ok(status) => {
            let available = status.success();
            YARA_AVAILABLE.store(if available { 1 } else { 0 }, Ordering::Relaxed);
            available
        }
        Err(_) => {
            YARA_AVAILABLE.store(0, Ordering::Relaxed);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_categorize_trojan() {
        let (level, name) = categorize_rule("Trojan.Win32.Generic");
        assert_eq!(level, ThreatLevel::Malicious);
        assert_eq!(name, "Trojan.Win32.Generic");
    }

    #[test]
    fn test_categorize_adware() {
        let (level, _name) = categorize_rule("PUP.Generic.Adware");
        assert_eq!(level, ThreatLevel::Suspicious);
    }

    #[test]
    fn test_parse_yara_output() {
        let output = "Trojan.Win32.Generic /tmp/virus.exe\n";
        let result = parse_yara_output(output).unwrap();
        assert!(result.is_some());
        let detection = result.unwrap();
        assert_eq!(
            detection.rule_matched,
            Some("Trojan.Win32.Generic".to_string())
        );
    }
}
