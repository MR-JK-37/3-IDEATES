// av-service/src/engines/signatures.rs
// Lightweight local signature engine for known high-confidence indicators.

use crate::engines::{DetectionResult, ThreatLevel};
use anyhow::Result;
use std::fs::File;
use std::io::Read;
use std::path::Path;

const MAX_SCAN_BYTES: usize = 8 * 1024 * 1024;
const EICAR: &str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

pub async fn scan(path: &Path) -> Result<Option<DetectionResult>> {
    let data = read_prefix(path, MAX_SCAN_BYTES)?;
    if data.is_empty() {
        return Ok(None);
    }

    // High-confidence known test-malware signature.
    if contains_ascii(&data, EICAR) {
        return Ok(Some(DetectionResult {
            level: ThreatLevel::Malicious,
            engine: "LocalSignatures".to_string(),
            threat_name: "EICAR-Test-File".to_string(),
            confidence: 1.0,
            signature: Some("eicar".to_string()),
            rule_matched: None,
        }));
    }

    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    // Script malware patterns: require multiple independent indicators.
    if matches!(
        ext.as_str(),
        "ps1" | "bat" | "cmd" | "js" | "vbs" | "sh" | "py"
    ) {
        let text = String::from_utf8_lossy(&data).to_ascii_lowercase();
        let indicators = [
            "invoke-mimikatz",
            "frombase64string(",
            "iex (new-object net.webclient).downloadstring(",
            "powershell -enc",
            "mshta http",
            "regsvr32 /s /u /i:http",
            "rundll32",
            "createobject(\"wscript.shell\")",
        ];
        let hits = indicators.iter().filter(|k| text.contains(**k)).count();
        if hits >= 2 {
            return Ok(Some(DetectionResult {
                level: ThreatLevel::Malicious,
                engine: "LocalSignatures".to_string(),
                threat_name: format!("Malicious.Script.Patterns({hits})"),
                confidence: 0.95,
                signature: None,
                rule_matched: None,
            }));
        }

        // RAT-style behavior scoring (network control + host abuse indicators).
        let rat_indicators = [
            "socket.connect(",
            "reverse shell",
            "pynput",
            "keylogger",
            "pyautogui.screenshot",
            "cv2.videocapture",
            "subprocess.popen(",
            "os.system(",
            "registry.run",
            "startup",
            "taskschd",
            "base64.b64decode(",
            "requests.post(",
            "webhook",
            "discord.com/api/webhooks",
        ];
        let rat_hits = rat_indicators.iter().filter(|k| text.contains(**k)).count();
        let has_c2 = text.contains("socket.connect(")
            || text.contains("requests.post(")
            || text.contains("webhook");
        let has_execution = text.contains("subprocess.popen(")
            || text.contains("os.system(")
            || text.contains("powershell -enc");

        if rat_hits >= 4 && has_c2 && has_execution {
            return Ok(Some(DetectionResult {
                level: ThreatLevel::Suspicious,
                engine: "LocalSignatures".to_string(),
                threat_name: format!("RAT.Behavioral.Patterns({rat_hits})"),
                confidence: 0.88,
                signature: None,
                rule_matched: None,
            }));
        }

        // Android RAT builder patterns (high-confidence when C2 + persistence + exec coexist).
        let android_rat_markers = [
            "api.telegram.org/bot",
            "receive_boot_completed",
            "startforegroundservice",
            "runtime.getruntime().exec",
            "android.permission.read_sms",
            "android.permission.read_call_log",
            "android.permission.camera",
            "android.permission.record_audio",
        ];
        let android_hits = android_rat_markers
            .iter()
            .filter(|k| text.contains(**k))
            .count();
        let android_c2 = text.contains("api.telegram.org/bot");
        let android_exec = text.contains("runtime.getruntime().exec");
        let android_persist =
            text.contains("receive_boot_completed") || text.contains("startforegroundservice");

        if android_hits >= 4 && android_c2 && android_exec && android_persist {
            return Ok(Some(DetectionResult {
                level: ThreatLevel::Malicious,
                engine: "LocalSignatures".to_string(),
                threat_name: format!("Android.RAT.Builder({android_hits})"),
                confidence: 0.96,
                signature: None,
                rule_matched: None,
            }));
        }
    }

    Ok(None)
}

fn read_prefix(path: &Path, max_len: usize) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut data = Vec::with_capacity(max_len.min(1024 * 1024));
    let mut chunk = [0u8; 8192];

    loop {
        if data.len() >= max_len {
            break;
        }
        let read_len = (max_len - data.len()).min(chunk.len());
        let n = file.read(&mut chunk[..read_len])?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&chunk[..n]);
    }
    Ok(data)
}

fn contains_ascii(data: &[u8], pattern: &str) -> bool {
    let text = String::from_utf8_lossy(data);
    text.contains(pattern)
}
