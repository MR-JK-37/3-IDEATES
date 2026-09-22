use sha2::{Digest, Sha256};
use std::path::Path;
use std::fs;
use anyhow::Context;
use regex::Regex;
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use crate::hashdb;
use crate::vt::virustotal_check;

#[derive(Debug)]
pub enum ScanResult {
    Clean,
    Malicious { engine: String, detail: String },
}

/// Scan a file using multiple local engines: ClamAV (clamscan) and YARA (yara).
/// This implementation calls external CLIs as an initial production-ready integration.
pub async fn scan_file(path: &Path) -> anyhow::Result<ScanResult> {
    // Read file for local heuristics (entropy) and hashing
    let data = fs::read(path).with_context(|| format!("reading file {}", path.display()))?;

    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    let hash_hex = hex::encode(hash);

    let entropy = calculate_entropy(&data);

    println!("Scan start: {} sha256={} entropy={:.2}", path.display(), hash_hex, entropy);

    // 1 - Quick heuristic: high entropy => suspicious
    if entropy > 7.8 {
        return Ok(ScanResult::Malicious { engine: "Heuristic".into(), detail: "High entropy (possible packer)".into() });
    }

    // 2 - Check local hash DB before running heavier engines
    // run blocking DB query in a thread
    if let Ok(Some(name)) = tokio::task::spawn_blocking({
        let h = hash_hex.clone();
        move || hashdb::check_hash(&h)
    }).await.context("hashdb task")? {
        return Ok(ScanResult::Malicious { engine: "HashDB".into(), detail: name });
    }

    // 3 - Run ClamAV (clamscan). Requires `clamscan` in PATH or provide clamdscan alternative.
    match run_clamscan(path).await {
        Ok(Some(virus_name)) => {
            return Ok(ScanResult::Malicious { engine: "ClamAV".into(), detail: virus_name });
        }
        Ok(None) => { /* clean */ }
        Err(e) => eprintln!("ClamAV scan error: {}", e),
    }

    // 3 - Run YARA rules if configured via YARA_RULES env var (path to rule file or dir)
    if let Ok(rules_path) = std::env::var("YARA_RULES") {
        match run_yara(&rules_path, path).await {
            Ok(Some(rule)) => {
                return Ok(ScanResult::Malicious { engine: "YARA".into(), detail: rule });
            }
            Ok(None) => {}
            Err(e) => eprintln!("YARA scan error: {}", e),
        }
    }

    // 4 - If still clean, optionally query VirusTotal (if API key provided) and add to local DB on positive
    if let Ok(api_key) = std::env::var("VT_API_KEY") {
        match virustotal_check(&hash_hex, &api_key).await {
            Ok(Some(res)) => {
                let detail = format!("VirusTotal: {}", res.summary);
                // add to local DB for future quick checks
                let _ = tokio::task::spawn_blocking({
                    let h = hash_hex.clone();
                    let d = detail.clone();
                    move || hashdb::add_hash(&h, &d, "VirusTotal")
                }).await;
                return Ok(ScanResult::Malicious { engine: "VirusTotal".into(), detail });
            }
            Ok(None) => {}
            Err(e) => eprintln!("VirusTotal error: {}", e),
        }
    }

    Ok(ScanResult::Clean)
}

async fn run_clamscan(path: &Path) -> anyhow::Result<Option<String>> {
    // Use a timeout to keep real-time latency bounded
    let cmd = Command::new("clamscan")
        .arg("--no-summary")
        .arg(path.as_os_str())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    let dur = Duration::from_millis(2000);
    let output = timeout(dur, cmd.wait_with_output()).await??;

    let out = String::from_utf8_lossy(&output.stdout);
    // clamscan output: "/path/to/file: OK" or "/path/to/file: Eicar-Test-Signature FOUND"
    let re = Regex::new(r":\s*(.*)(?:\sFOUND)?$")?;
    for line in out.lines() {
        if line.trim().is_empty() { continue; }
        if line.contains(": OK") { continue; }
        if let Some(cap) = re.captures(line) {
            let name = cap.get(1).map(|m| m.as_str().trim().to_string()).unwrap_or_else(|| "Unknown".into());
            if name != "OK" {
                return Ok(Some(name));
            }
        }
    }
    Ok(None)
}

async fn run_yara(rules_path: &str, path: &Path) -> anyhow::Result<Option<String>> {
    let cmd = Command::new("yara")
        .arg("-r")
        .arg(rules_path)
        .arg(path.as_os_str())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    let dur = Duration::from_millis(2000);
    let output = timeout(dur, cmd.wait_with_output()).await??;
    let out = String::from_utf8_lossy(&output.stdout);
    // yara output: "rule_name <path>"
    for line in out.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() { continue; }
        let rule = parts[0].to_string();
        return Ok(Some(rule));
    }
    Ok(None)
}

fn calculate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    if len == 0.0 { return 0.0; }
    let mut ent = 0.0f64;
    for &c in &counts {
        if c == 0 { continue; }
        let p = (c as f64) / len;
        ent -= p * p.log2();
    }
    ent
}
