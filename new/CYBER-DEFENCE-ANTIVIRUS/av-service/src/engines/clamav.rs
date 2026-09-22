// av-service/src/engines/clamav.rs
// ClamAV integration for malware detection

use crate::engines::{DetectionResult, ThreatLevel};
use anyhow::Result;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicI8, Ordering};
use tokio::process::Command;
use tokio::time::{timeout, Duration};

static CLAMSCAN_AVAILABLE: AtomicI8 = AtomicI8::new(-1); // -1 unknown, 0 no, 1 yes

pub async fn scan(path: &Path) -> Result<Option<DetectionResult>> {
    // Check if clamscan is available
    if !is_clamscan_available().await {
        log::debug!("ClamAV not available, skipping");
        return Ok(None);
    }

    // Run clamscan with timeout
    let output = timeout(
        Duration::from_secs(10),
        Command::new("clamscan")
            .arg("--no-summary")
            .arg("--stdout")
            .arg(path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output(),
    )
    .await;

    match output {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_clamscan_output(&stdout, path)
        }
        Ok(Err(e)) => {
            log::warn!("ClamAV execution error: {}", e);
            Ok(None)
        }
        Err(_) => {
            log::warn!("ClamAV scan timeout");
            Ok(None)
        }
    }
}

fn parse_clamscan_output(output: &str, path: &Path) -> Result<Option<DetectionResult>> {
    // clamscan output format: "/path/to/file: Trojan.Generic FOUND"
    // or "/path/to/file: OK"

    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }

        if line.contains(": OK") {
            return Ok(None); // File is clean
        }

        if line.contains("FOUND") {
            // Parse threat name
            if let Some(colon_pos) = line.find(": ") {
                let after_colon = &line[colon_pos + 2..];
                if let Some(found_pos) = after_colon.find(" FOUND") {
                    let threat_name = after_colon[..found_pos].trim().to_string();

                    return Ok(Some(DetectionResult {
                        level: ThreatLevel::Malicious,
                        engine: "ClamAV".to_string(),
                        threat_name,
                        confidence: 0.95,
                        signature: Some(format!("ClamAV-{}", path.display())),
                        rule_matched: None,
                    }));
                }
            }
        }
    }

    Ok(None)
}

async fn is_clamscan_available() -> bool {
    match CLAMSCAN_AVAILABLE.load(Ordering::Relaxed) {
        0 => return false,
        1 => return true,
        _ => {}
    }

    match Command::new("clamscan")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
    {
        Ok(status) => {
            let available = status.success();
            CLAMSCAN_AVAILABLE.store(if available { 1 } else { 0 }, Ordering::Relaxed);
            available
        }
        Err(_) => {
            CLAMSCAN_AVAILABLE.store(0, Ordering::Relaxed);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_clamscan_ok() {
        let output = "/tmp/test.txt: OK\n";
        let result = parse_clamscan_output(output, Path::new("/tmp/test.txt")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_clamscan_infected() {
        let output = "/tmp/virus.exe: Trojan.Generic FOUND\n";
        let result = parse_clamscan_output(output, Path::new("/tmp/virus.exe")).unwrap();

        assert!(result.is_some());
        let detection = result.unwrap();
        assert_eq!(detection.threat_name, "Trojan.Generic");
        assert_eq!(detection.level, ThreatLevel::Malicious);
    }
}
