// av-service/src/engines/heuristics.rs
// File analysis and heuristic threat detection

use crate::engines::{DetectionResult, ThreatLevel};
use anyhow::Result;
use std::fs::File;
use std::io::Read;
use std::path::Path;

const MAX_HEURISTIC_BYTES: usize = 10 * 1024 * 1024;

pub async fn analyze_file(path: &Path) -> Result<DetectionResult> {
    let data = read_prefix(path, MAX_HEURISTIC_BYTES)?;
    let entropy = calculate_entropy(&data);
    let ext = extension(path);
    let executable_like = is_executable_like(ext);
    let document_or_media = is_document_or_media(ext);

    // Check for suspicious characteristics
    let mut threat_level = ThreatLevel::Clean;
    let mut threat_name = String::new();
    let mut confidence = 0.0f32;

    // High-entropy checks are limited to executable/script-like content.
    if entropy > 7.8 && (executable_like || is_script_file(path)) {
        if has_pack_signature(&data) {
            threat_level = ThreatLevel::Suspicious;
            threat_name = "Packed.Binary".to_string();
            confidence = 0.6;
        } else if entropy > 7.95 {
            threat_level = ThreatLevel::Suspicious;
            threat_name = "Encrypted.Payload".to_string();
            confidence = 0.5;
        }
    }

    // Check for obfuscated scripts
    if is_script_file(path) && contains_obfuscation_markers(&data) {
        threat_level = ThreatLevel::Suspicious;
        threat_name = "Obfuscated.Script".to_string();
        confidence = 0.7;
    }

    // Detect embedded executables
    if let Some(embedded_exe) = find_embedded_executable(path, &data) {
        threat_level = ThreatLevel::Suspicious;
        threat_name = format!("EmbeddedExe.{}", embedded_exe);
        confidence = 0.75;
    }

    // Suspicious string analysis (basic)
    let suspicious_count = count_suspicious_strings(&data);
    if suspicious_count > 10 {
        threat_level = ThreatLevel::Suspicious;
        threat_name = format!("SuspiciousStrings.Count{}", suspicious_count);
        confidence = (suspicious_count as f32 / 50.0).min(0.9);
    }

    // Guardrail: avoid aggressive detections on common benign document/media files
    // unless multiple strong indicators are present.
    if document_or_media
        && matches!(threat_level, ThreatLevel::Suspicious)
        && confidence < 0.85
        && !has_valid_pe(&data)
    {
        threat_level = ThreatLevel::Clean;
        threat_name.clear();
        confidence = 0.0;
    }

    Ok(DetectionResult {
        level: threat_level,
        engine: "Heuristic".to_string(),
        threat_name,
        confidence,
        signature: None,
        rule_matched: None,
    })
}

fn extension(path: &Path) -> &str {
    path.extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .trim()
}

fn is_executable_like(ext: &str) -> bool {
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "exe" | "dll" | "sys" | "so" | "bin" | "elf" | "run" | "com"
    )
}

fn is_document_or_media(ext: &str) -> bool {
    matches!(
        ext.to_ascii_lowercase().as_str(),
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
            | "wav"
            | "flac"
            | "mp4"
            | "avi"
            | "mkv"
    )
}

pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}

pub fn calculate_entropy_from_path(path: &Path) -> Result<f64> {
    let data = read_prefix(path, MAX_HEURISTIC_BYTES)?;
    Ok(calculate_entropy(&data))
}

fn read_prefix(path: &Path, max_len: usize) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut data = Vec::with_capacity(max_len.min(1024 * 1024));
    let mut chunk = [0u8; 8192];

    loop {
        if data.len() >= max_len {
            break;
        }

        let remaining = max_len - data.len();
        let read_len = remaining.min(chunk.len());
        let n = file.read(&mut chunk[..read_len])?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&chunk[..n]);
    }

    Ok(data)
}

fn has_pack_signature(data: &[u8]) -> bool {
    // Common packer signatures
    let packers: &[&[u8]] = &[
        b"UPX",                         // UPX packer
        b"!This program cannot be run", // Stub indicator
        b"Themida",                     // Themida packer
    ];

    for sig in packers {
        if data.windows(sig.len()).any(|w| w == *sig) {
            return true;
        }
    }

    false
}

fn is_script_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|s| s.to_str()),
        Some("vbs" | "js" | "bat" | "cmd" | "ps1" | "py" | "sh")
    )
}

fn contains_obfuscation_markers(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);

    // Check for obfuscation patterns
    let obfuscation_indicators = [
        "String.fromCharCode",
        "eval(",
        "exec(",
        "ProcessBuilder",
        "Runtime.getRuntime",
        "java/lang/Runtime",
        "reflection",
        "weaksauce", // PowerShell obfuscation
    ];

    obfuscation_indicators
        .iter()
        .filter(|ind| text.contains(*ind))
        .count()
        >= 2
}

fn has_valid_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    e_lfanew + 4 <= data.len() && &data[e_lfanew..e_lfanew + 4] == b"PE\0\0"
}

fn find_embedded_executable(path: &Path, data: &[u8]) -> Option<String> {
    // Strict PE validation at offset 0 for executable-like names only.
    if has_valid_pe(data) && is_executable_like(extension(path)) {
        return Some("PE".to_string());
    }

    // Prevent noisy false positives in common document/media files.
    if is_document_or_media(extension(path)) {
        return None;
    }

    // Look for ELF header
    if data.starts_with(b"\x7FELF") {
        return Some("ELF".to_string());
    }

    // Look for Mach-O header
    if data.starts_with(b"\xFE\xED\xFA") || data.starts_with(b"\xCA\xFE\xBA") {
        return Some("MachO".to_string());
    }

    // Embedded PE detection: require MZ + nearby PE header, and only search bounded prefix.
    let upper = data.len().min(128 * 1024);
    let mut pos = 512usize;
    while pos + 2 < upper {
        if data[pos] == b'M' && data[pos + 1] == b'Z' {
            let pe_search_end = (pos + 512).min(upper.saturating_sub(4));
            let mut i = pos + 2;
            while i < pe_search_end {
                if &data[i..i + 4] == b"PE\0\0" {
                    return Some("PE".to_string());
                }
                i += 1;
            }
        }
        pos += 1;
    }

    None
}

fn count_suspicious_strings(data: &[u8]) -> usize {
    let text = String::from_utf8_lossy(data);
    let suspicious_patterns = [
        "cmd.exe",
        "powershell",
        "cmd /c",
        "CreateRemoteThread",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "SetWindowsHookEx",
        "GetProcAddress",
        "LoadLibrary",
        "ShellExecute",
        "WinExec",
        "GetSystemDirectory",
        "CreateProcess",
        "RegOpenKey",
        "RegSetValue",
        "GetModuleHandle",
    ];

    suspicious_patterns
        .iter()
        .filter(|pattern| text.to_lowercase().contains(&pattern.to_lowercase()))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let random_data = vec![0u8; 1000]; // Zeros should have very low entropy
        let entropy = calculate_entropy(&random_data);
        assert!(entropy < 1.0);

        // High entropy data (should be > 7.0)
        let mut high_entropy = Vec::new();
        for i in 0..1000 {
            high_entropy.push((i % 256) as u8);
        }
        let entropy = calculate_entropy(&high_entropy);
        assert!(entropy > 6.0);
    }

    #[test]
    fn test_suspicious_strings() {
        let data_with_suspicious = b"CreateRemoteThread cmd.exe powershell";
        let count = count_suspicious_strings(data_with_suspicious);
        assert!(count >= 2);
    }
}
