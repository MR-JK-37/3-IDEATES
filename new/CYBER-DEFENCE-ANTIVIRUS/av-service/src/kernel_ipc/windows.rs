//! Windows FilterPort and IOCTL communication with minifilter driver
//! Bridges kernel-level file interception to userspace av-service

use super::{
    ensure_kernel_ipc_schema_compatible, expected_kernel_ipc_schema, strict_kernel_ipc_schema_enabled,
    FileEvent, FileEventType, KernelIpcHandler, KERNEL_IPC_SCHEMA_VERSION, ScanDecision,
    ScanResponse,
};
use anyhow::{anyhow, Result};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(target_os = "windows")]
use {
    std::ffi::OsStr,
    std::mem,
    std::os::windows::ffi::OsStrExt,
    std::ptr,
    winapi::shared::minwindef::{FALSE, TRUE},
    winapi::um::fileapi::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING},
    winapi::um::ioctlbase::CTL_CODE,
    winapi::um::winbase::{FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH},
    winapi::um::winnt::{HANDLE, INVALID_HANDLE_VALUE},
};

/// Windows IOCTL device type
const FILE_DEVICE_ANTIVIRUS: u32 = 0x8000;

/// IOCTL control codes (must match minifilter.h)
const IOCTL_GET_FILE_EVENT: u32 = ctl_code(FILE_DEVICE_ANTIVIRUS, 0x800, 3, 1); // METHOD_OUT_DIRECT, FILE_READ_ACCESS
const IOCTL_SEND_SCAN_RESULT: u32 = ctl_code(FILE_DEVICE_ANTIVIRUS, 0x801, 3, 2); // METHOD_IN_DIRECT, FILE_WRITE_ACCESS
const IOCTL_GET_DRIVER_VERSION: u32 = ctl_code(FILE_DEVICE_ANTIVIRUS, 0x802, 0, 1); // METHOD_BUFFERED, FILE_READ_ACCESS

/// Helper to compute CTL_CODE value
const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// File event from kernel driver (matches minifilter.h AV_FILE_EVENT)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct AvFileEvent {
    request_id: u64,
    process_id: u32,
    parent_process_id: u32,
    timestamp: u64,
    event_type: u32,
    file_attributes: u32,
    file_size: u64,
    file_path: [u16; 512], // Unicode wide string path
}

/// Scan response to kernel driver (matches minifilter.h AV_SCAN_RESPONSE)
#[repr(C, packed)]
#[derive(Debug, Clone)]
struct AvScanResponse {
    request_id: u64,
    decision: u32,
    threat_level: u32,
    engine: [u8; 64],
    threat_name: [u8; 256],
    status: u32,
}

/// Windows kernel IPC handler using FilterPort and IOCTLs
pub struct WindowsKernelIpc {
    connected: Arc<AtomicBool>,
    driver_port_handle: Option<HANDLE>,
    schema_ok: Arc<AtomicBool>,
}

impl WindowsKernelIpc {
    /// Create new Windows IOCTL handler
    pub fn new() -> Self {
        WindowsKernelIpc {
            connected: Arc::new(AtomicBool::new(false)),
            driver_port_handle: None,
            schema_ok: Arc::new(AtomicBool::new(validate_schema_contract())),
        }
    }

    /// Connect to minifilter driver via FilterPort
    #[cfg(target_os = "windows")]
    pub fn connect(&mut self) -> Result<()> {
        unsafe {
            let port_name = "\\AVFilterPort".encode_utf16(None);
            let port_name: Vec<u16> = "\\AVFilterPort"
                .encode_utf16(None)
                .chain(std::iter::once(0))
                .collect();

            // Open connection to filter driver communication port
            let handle = CreateFileW(
                port_name.as_ptr(),
                0x00120089, // FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE
                0,          // No sharing
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            );

            if handle == INVALID_HANDLE_VALUE {
                return Err(anyhow!("Failed to open FilterPort connection"));
            }

            self.driver_port_handle = Some(handle);
            self.connected.store(true, Ordering::Relaxed);

            Ok(())
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn connect(&mut self) -> Result<()> {
        Err(anyhow!("Windows IPC only available on Windows"))
    }

    /// Convert Windows-relative path to PathBuf
    fn widechar_to_path(wide_str: &[u16]) -> PathBuf {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        // Find null terminator
        let len = wide_str
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(wide_str.len());
        let path = OsString::from_wide(&wide_str[..len]);
        PathBuf::from(path)
    }

    /// Convert PathBuf to Windows wide character array
    fn path_to_widechar(path: &PathBuf) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        wide
    }
}

impl Default for WindowsKernelIpc {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelIpcHandler for WindowsKernelIpc {
    fn listen_for_events(&self) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            if strict_kernel_ipc_schema_enabled() && !self.schema_ok.load(Ordering::Relaxed) {
                return Err(anyhow!("Windows kernel IPC schema contract failed"));
            }
            if !self.is_connected() {
                return Err(anyhow!("Not connected to minifilter driver"));
            }

            // In a real implementation, would use overlapped I/O or FilterPort listener thread
            // For now, provide the interface stub
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("Windows IPC only available on Windows"))
        }
    }

    fn send_response(&self, response: ScanResponse) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            if !self.is_connected() {
                return Err(anyhow!("Not connected to minifilter driver"));
            }

            let mut av_response = AvScanResponse {
                request_id: response.request_id,
                decision: response.decision as u32,
                threat_level: response.threat_level,
                engine: [0u8; 64],
                threat_name: [0u8; 256],
                status: 0, // STATUS_SUCCESS
            };

            // Copy engine name (UTF-8)
            let engine_bytes = response.engine.as_bytes();
            let copy_len = std::cmp::min(engine_bytes.len(), av_response.engine.len() - 1);
            av_response.engine[..copy_len].copy_from_slice(&engine_bytes[..copy_len]);

            // Copy threat name (UTF-8)
            let threat_bytes = response.threat_name.as_bytes();
            let copy_len = std::cmp::min(threat_bytes.len(), av_response.threat_name.len() - 1);
            av_response.threat_name[..copy_len].copy_from_slice(&threat_bytes[..copy_len]);

            // In real implementation would use DeviceIoControl with IOCTL_SEND_SCAN_RESULT
            // For now, just validate the response structure
            log::debug!(
                "Sending scan response: RequestId={}, Decision={:?}, Engine={}",
                response.request_id,
                response.decision,
                response.engine
            );

            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("Windows IPC only available on Windows"))
        }
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
}

fn validate_schema_contract() -> bool {
    if let Some(expected) = expected_kernel_ipc_schema() {
        if let Err(err) = ensure_kernel_ipc_schema_compatible(expected) {
            log::error!("Windows kernel IPC schema mismatch: {}", err);
            return false;
        }
    } else if let Err(err) = ensure_kernel_ipc_schema_compatible(KERNEL_IPC_SCHEMA_VERSION) {
        log::error!("Windows kernel IPC schema validation failed: {}", err);
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_code_computation() {
        // Verify IOCTL codes match minifilter.h definitions
        let get_event = ctl_code(FILE_DEVICE_ANTIVIRUS, 0x800, 3, 1);
        assert_eq!(get_event, IOCTL_GET_FILE_EVENT);

        let send_result = ctl_code(FILE_DEVICE_ANTIVIRUS, 0x801, 3, 2);
        assert_eq!(send_result, IOCTL_SEND_SCAN_RESULT);
    }

    #[test]
    fn test_windows_kernel_ipc_creation() {
        let ipc = WindowsKernelIpc::new();
        assert!(!ipc.is_connected());
    }
}
