//! Kernel-level IPC module for cross-platform communication
//! Provides unified interface to eBPF (Linux), minifilter (Windows), and EndpointSecurity (macOS)

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

use std::path::PathBuf;

pub const KERNEL_IPC_SCHEMA_VERSION: u16 = 1;

pub fn strict_kernel_ipc_schema_enabled() -> bool {
    std::env::var("AV_KERNEL_IPC_STRICT_SCHEMA")
        .unwrap_or_else(|_| "true".to_string())
        != "false"
}

pub fn expected_kernel_ipc_schema() -> Option<u16> {
    std::env::var("AV_KERNEL_IPC_SCHEMA_VERSION_EXPECTED")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
}

pub fn ensure_kernel_ipc_schema_compatible(received: u16) -> anyhow::Result<()> {
    if received != KERNEL_IPC_SCHEMA_VERSION {
        anyhow::bail!(
            "kernel IPC schema mismatch: received {}, expected {}",
            received,
            KERNEL_IPC_SCHEMA_VERSION
        );
    }
    Ok(())
}

/// File event from kernel to userspace
#[derive(Debug, Clone)]
pub struct FileEvent {
    pub request_id: u64,
    pub process_id: u32,
    pub parent_process_id: u32,
    pub timestamp: u64,
    pub event_type: FileEventType,
    pub file_path: PathBuf,
    pub file_size: u64,
}

/// Type of file system event
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FileEventType {
    Create = 0x01,
    Delete = 0x02,
    Write = 0x04,
    Rename = 0x08,
    Execute = 0x10,
}

/// Scan decision from userspace to kernel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ScanDecision {
    Allow = 0,
    Block = 1,
    Quarantine = 2,
    Unknown = 3,
}

/// Scan response with reasoning
#[derive(Debug, Clone)]
pub struct ScanResponse {
    pub request_id: u64,
    pub decision: ScanDecision,
    pub threat_level: u32,   // 0=clean, 1-3=suspicious, 4-5=malicious
    pub engine: String,      // ClamAV, YARA, VirusTotal, Heuristic
    pub threat_name: String, // Threat name/signature
}

/// Generic kernel IPC handler
pub trait KernelIpcHandler: Send + Sync {
    /// Listen for file events from kernel
    fn listen_for_events(&self) -> anyhow::Result<()>;

    /// Send scan response back to kernel
    fn send_response(&self, response: ScanResponse) -> anyhow::Result<()>;

    /// Check if kernel driver is connected
    fn is_connected(&self) -> bool;
}

#[cfg(target_os = "linux")]
pub use linux::LinuxKernelIpc as PlatformKernelIpc;

#[cfg(target_os = "windows")]
pub use windows::WindowsKernelIpc as PlatformKernelIpc;

#[cfg(target_os = "macos")]
pub use macos::MacOSKernelIpc as PlatformKernelIpc;
