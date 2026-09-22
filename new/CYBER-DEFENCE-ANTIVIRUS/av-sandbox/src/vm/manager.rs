use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

#[derive(Debug)]
pub struct VMManager {
    enabled: bool,
    workspace: PathBuf,
    image: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxReport {
    pub file_path: String,
    pub execution_time_ms: u64,
    pub verdict: SandboxVerdict,
    pub suspicious_syscalls: Vec<String>,
    pub network_connections: Vec<NetworkConnection>,
    pub file_modifications: Vec<FileModification>,
    pub process_creations: Vec<ProcessCreation>,
    pub api_calls: Vec<APICall>,
    pub risk_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SandboxVerdict {
    Clean,
    Suspicious,
    Malicious,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: String,
    pub destination: String,
    pub port: u16,
    pub direction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileModification {
    pub path: String,
    pub operation: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessCreation {
    pub process_name: String,
    pub command_line: String,
    pub parent_pid: u32,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APICall {
    pub function: String,
    pub module: String,
    pub parameters: Vec<String>,
    pub result: String,
}

impl VMManager {
    pub fn new() -> Result<Self> {
        let workspace = std::env::var("SANDBOX_WORKDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("cybershield-sandbox"));
        std::fs::create_dir_all(&workspace)?;

        let enabled = docker_available();
        if enabled {
            info!("Sandbox runtime ready: Docker");
        } else {
            warn!("Docker not available; sandbox will run in offline mode");
        }

        Ok(Self {
            enabled,
            workspace,
            image: std::env::var("SANDBOX_IMAGE")
                .unwrap_or_else(|_| "cybershield/sandbox:latest".to_string()),
        })
    }

    pub fn offline() -> Self {
        Self {
            enabled: false,
            workspace: std::env::temp_dir().join("cybershield-sandbox"),
            image: "cybershield/sandbox:latest".to_string(),
        }
    }

    pub async fn execute_in_sandbox(&self, file_path: &str) -> Result<SandboxReport> {
        if !self.enabled {
            return self.offline_analysis(file_path).await;
        }
        self.analyze_with_docker(file_path).await
    }

    async fn analyze_with_docker(&self, file_path: &str) -> Result<SandboxReport> {
        let target = Path::new(file_path);
        if !target.exists() || !target.is_file() {
            return Err(anyhow!("target file missing: {}", file_path));
        }

        let session = uuid::Uuid::new_v4().to_string();
        let session_dir = self.workspace.join(session);
        let input_dir = session_dir.join("input");
        let output_dir = session_dir.join("output");
        std::fs::create_dir_all(&input_dir)?;
        std::fs::create_dir_all(&output_dir)?;

        let name = target
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("invalid target file name"))?;
        let copied_target = input_dir.join(name);
        tokio::fs::copy(target, &copied_target)
            .await
            .with_context(|| format!("copying {} to sandbox workspace", file_path))?;

        info!("Running docker sandbox for {}", file_path);
        let output = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--network",
                "none",
                "--memory",
                "512m",
                "--cpus",
                "1",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "-v",
            ])
            .arg(format!("{}:/input:ro", input_dir.display()))
            .arg("-v")
            .arg(format!("{}:/output", output_dir.display()))
            .arg(&self.image)
            .arg("/malware/monitor.sh")
            .arg(format!("/input/{}", name))
            .output()
            .context("starting docker sandbox container")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("sandbox container failed: {}", stderr.trim()));
        }

        let report_path = output_dir.join("report.json");
        let report_raw = tokio::fs::read_to_string(&report_path)
            .await
            .with_context(|| format!("missing sandbox report at {}", report_path.display()))?;
        let mut report: SandboxReport =
            serde_json::from_str(&report_raw).context("invalid sandbox report format")?;
        report.file_path = file_path.to_string();

        let _ = tokio::fs::remove_dir_all(session_dir).await;
        Ok(report)
    }

    async fn offline_analysis(&self, file_path: &str) -> Result<SandboxReport> {
        Ok(SandboxReport {
            file_path: file_path.to_string(),
            execution_time_ms: 0,
            verdict: SandboxVerdict::Unknown,
            suspicious_syscalls: vec![],
            network_connections: vec![],
            file_modifications: vec![],
            process_creations: vec![],
            api_calls: vec![],
            risk_score: 0.0,
        })
    }
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offline_mode() {
        let manager = VMManager::offline();
        assert!(!manager.enabled);
    }

    #[tokio::test]
    async fn test_offline_analysis() {
        let manager = VMManager::offline();
        let report = manager
            .execute_in_sandbox("/tmp/missing.bin")
            .await
            .unwrap();
        assert_eq!(report.verdict, SandboxVerdict::Unknown);
    }
}
