// av-service/src/engines/ml.rs
// Lightweight trainable malware risk model.
//
// This is not a large language model; it is a local logistic scorer with
// configurable weights. It is intentionally cheap to run in real-time.

use crate::engines::{DetectionResult, ThreatLevel};
use anyhow::Result;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;

const MAX_MODEL_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_MODEL_PATH: &str = "config/ml/risk_model.json";

#[derive(Debug, Clone, Deserialize)]
pub struct RiskModel {
    pub bias: f32,
    pub w_entropy: f32,
    pub w_executable_ext: f32,
    pub w_script_ext: f32,
    pub w_doc_or_media_ext: f32,
    pub w_valid_pe: f32,
    pub w_embedded_pe: f32,
    pub w_obfuscation: f32,
    pub w_suspicious_strings: f32,
    pub suspicious_threshold: f32,
    pub malicious_threshold: f32,
}

impl Default for RiskModel {
    fn default() -> Self {
        Self {
            bias: -4.5,
            w_entropy: 0.6,
            w_executable_ext: 2.6,
            w_script_ext: 2.2,
            w_doc_or_media_ext: -1.8,
            w_valid_pe: 3.0,
            w_embedded_pe: 1.3,
            w_obfuscation: 2.0,
            w_suspicious_strings: 1.8,
            suspicious_threshold: 0.72,
            malicious_threshold: 0.90,
        }
    }
}

static MODEL: Lazy<RiskModel> = Lazy::new(|| {
    let path =
        std::env::var("AV_RISK_MODEL_PATH").unwrap_or_else(|_| DEFAULT_MODEL_PATH.to_string());
    match load_model(Path::new(&path)) {
        Ok(model) => model,
        Err(e) => {
            log::warn!(
                "ML model not loaded from {} ({}). AI-RiskModel engine disabled.",
                path,
                e
            );
            RiskModel {
                suspicious_threshold: 2.0,
                malicious_threshold: 2.0,
                ..RiskModel::default()
            }
        }
    }
});

#[derive(Debug, Clone, Copy)]
struct Features {
    entropy: f32,
    executable_ext: f32,
    script_ext: f32,
    doc_or_media_ext: f32,
    valid_pe: f32,
    embedded_pe: f32,
    obfuscation: f32,
    suspicious_strings: f32,
}

pub async fn score_file(path: &Path) -> Result<Option<DetectionResult>> {
    let data = read_prefix(path, 5 * 1024 * 1024)?;
    if data.is_empty() {
        return Ok(None);
    }

    let f = extract_features(path, &data);
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    // Strong false-positive guardrails:
    // image/text docs cannot execute on their own and are often compressed.
    let non_exec = is_non_executable_content_ext(&ext);
    let screenshot_like = file_name.contains("screenshot")
        || file_name.starts_with("img_")
        || file_name.contains("capture");
    let has_strong_executable_signals =
        f.valid_pe > 0.0 || f.embedded_pe > 0.0 || f.obfuscation > 0.0 || f.suspicious_strings >= 0.5;

    if non_exec && (screenshot_like || !has_strong_executable_signals) {
        return Ok(None);
    }

    let model = &*MODEL;
    let raw = model.bias
        + model.w_entropy * f.entropy
        + model.w_executable_ext * f.executable_ext
        + model.w_script_ext * f.script_ext
        + model.w_doc_or_media_ext * f.doc_or_media_ext
        + model.w_valid_pe * f.valid_pe
        + model.w_embedded_pe * f.embedded_pe
        + model.w_obfuscation * f.obfuscation
        + model.w_suspicious_strings * f.suspicious_strings;

    let score = sigmoid(raw);
    if non_exec && score < 0.97 {
        return Ok(None);
    }

    if score < model.suspicious_threshold {
        return Ok(None);
    }

    let (level, threat_name) = if score >= model.malicious_threshold {
        (ThreatLevel::Malicious, format!("ML.HighRisk({:.2})", score))
    } else {
        (
            ThreatLevel::Suspicious,
            format!("ML.Suspicious({:.2})", score),
        )
    };

    Ok(Some(DetectionResult {
        level,
        engine: "AI-RiskModel".to_string(),
        threat_name,
        confidence: score,
        signature: None,
        rule_matched: None,
    }))
}

fn load_model(path: &Path) -> Result<RiskModel> {
    let file = File::open(path)?;
    let mut buf = String::with_capacity(MAX_MODEL_BYTES);
    file.take(MAX_MODEL_BYTES as u64).read_to_string(&mut buf)?;
    let model: RiskModel = serde_json::from_str(&buf)?;
    Ok(model)
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

fn extract_features(path: &Path, data: &[u8]) -> Features {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    let executable_ext = is_executable_ext(&ext) as u8 as f32;
    let script_ext = is_script_ext(&ext) as u8 as f32;
    let doc_or_media_ext = is_doc_or_media_ext(&ext) as u8 as f32;
    let entropy = (crate::engines::heuristics::calculate_entropy(data) / 8.0) as f32;
    let valid_pe = has_valid_pe(data) as u8 as f32;
    let embedded_pe = has_embedded_pe(data) as u8 as f32;
    let obfuscation = contains_obfuscation_markers(data) as u8 as f32;
    let suspicious_strings = (count_suspicious_strings(data) as f32 / 16.0).min(1.0);

    Features {
        entropy,
        executable_ext,
        script_ext,
        doc_or_media_ext,
        valid_pe,
        embedded_pe,
        obfuscation,
        suspicious_strings,
    }
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

fn is_executable_ext(ext: &str) -> bool {
    matches!(ext, "exe" | "dll" | "sys" | "so" | "bin" | "run" | "elf")
}

fn is_script_ext(ext: &str) -> bool {
    matches!(
        ext,
        "ps1" | "js" | "vbs" | "bat" | "cmd" | "sh" | "py" | "rb"
    )
}

fn is_doc_or_media_ext(ext: &str) -> bool {
    matches!(
        ext,
        "pdf"
            | "doc"
            | "docx"
            | "xls"
            | "xlsx"
            | "ppt"
            | "pptx"
            | "txt"
            | "md"
            | "rtf"
            | "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "bmp"
            | "svg"
            | "mp3"
            | "mp4"
            | "avi"
            | "mkv"
            | "wav"
            | "flac"
    )
}

fn is_non_executable_content_ext(ext: &str) -> bool {
    matches!(
        ext,
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "bmp"
            | "svg"
            | "md"
            | "txt"
            | "rst"
            | "json"
            | "yaml"
            | "toml"
            | "csv"
            | "xml"
    )
}

fn has_valid_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    e_lfanew + 4 <= data.len() && &data[e_lfanew..e_lfanew + 4] == b"PE\0\0"
}

fn has_embedded_pe(data: &[u8]) -> bool {
    if data.len() < 0x200 {
        return false;
    }

    for pos in 512..data.len().saturating_sub(4).min(128 * 1024) {
        if data[pos] == b'M' && data[pos + 1] == b'Z' {
            let window_end = (pos + 512).min(data.len().saturating_sub(4));
            for off in (pos + 2)..window_end {
                if &data[off..off + 4] == b"PE\0\0" {
                    return true;
                }
            }
        }
    }
    false
}

fn contains_obfuscation_markers(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    let markers = [
        "String.fromCharCode",
        "eval(",
        "frombase64string(",
        "invoke-expression",
        "runtime.getruntime",
        "createobject(",
    ];
    markers
        .iter()
        .filter(|m| text.to_ascii_lowercase().contains(&m.to_ascii_lowercase()))
        .count()
        >= 2
}

fn count_suspicious_strings(data: &[u8]) -> usize {
    let text = String::from_utf8_lossy(data).to_ascii_lowercase();
    let patterns = [
        "cmd.exe",
        "powershell",
        "createprocess",
        "createremotethread",
        "writeprocessmemory",
        "loadlibrary",
        "winexec",
        "shell_execute",
    ];
    patterns.iter().filter(|p| text.contains(**p)).count()
}
