//! Linux kernel IPC via eBPF ringbuffer ingestion.

use super::{
    ensure_kernel_ipc_schema_compatible, expected_kernel_ipc_schema, strict_kernel_ipc_schema_enabled,
    KernelIpcHandler, KERNEL_IPC_SCHEMA_VERSION, ScanResponse,
};
use crate::kernel_comm::KernelEventMonitor;
use crate::kernel_events::{ensure_schema_compatible, KernelWireEvent};
use anyhow::{Context, Result};
use std::ffi::{c_char, c_int, c_long, c_ulong, c_void, CStr, CString};
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub enum ScanPriority {
    High,
    Low,
}

#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub path: PathBuf,
    pub priority: ScanPriority,
}

/// Linux kernel IPC handler using eBPF ringbuffer.
pub struct LinuxKernelIpc {
    connected: Arc<AtomicBool>,
    scan_queue: mpsc::UnboundedSender<ScanRequest>,
    schema_ok: Arc<AtomicBool>,
}

impl LinuxKernelIpc {
    /// Create new Linux kernel IPC handler
    pub fn new() -> Self {
        let (scan_queue, mut rx) = mpsc::unbounded_channel::<ScanRequest>();
        let in_progress = Arc::new(Mutex::new(HashMap::<PathBuf, Instant>::new()));
        let workers = Arc::new(Semaphore::new(4));
        let in_progress_bg = in_progress.clone();
        let workers_bg = workers.clone();

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                while let Some(req) = rx.recv().await {
                    let permit = match workers_bg.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => break,
                    };
                    let in_progress = in_progress_bg.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        scan_async(req, in_progress).await;
                    });
                }
            });
        }

        LinuxKernelIpc {
            connected: Arc::new(AtomicBool::new(true)), // Enabled by default on Linux
            scan_queue,
            schema_ok: Arc::new(AtomicBool::new(validate_schema_contract())),
        }
    }

    pub fn handle_event_async(&self, path: PathBuf) {
        let priority = if path.to_string_lossy().contains("Downloads") {
            ScanPriority::High
        } else {
            ScanPriority::Low
        };
        let _ = self.scan_queue.send(ScanRequest { path, priority });
    }
}

impl Default for LinuxKernelIpc {
    fn default() -> Self {
        Self::new()
    }
}

pub fn spawn_ringbuffer_consumer(
    monitor: KernelEventMonitor,
    event_seen: Arc<AtomicBool>,
    strict_schema: bool,
    kernel_only_mode: bool,
) -> JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let result = run_ringbuffer_consumer(&monitor, &event_seen, strict_schema, kernel_only_mode);
        if let Err(err) = result {
            tracing::error!("linux ringbuffer consumer stopped: {err}");
            if kernel_only_mode {
                std::process::exit(4);
            }
        }
    })
}

#[repr(C)]
struct EnforcePidValue {
    action: u8,
    reserved: [u8; 7],
    expires_at_ns: u64,
}

pub fn set_pid_enforcement_action(pid: u32, quarantine: bool) -> Result<()> {
    let action = if quarantine { 2_u8 } else { 1_u8 };
    let ttl_secs = std::env::var("AV_KERNEL_ENFORCEMENT_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(300);
    let expires_at_ns = monotonic_ns_now()
        .saturating_add(ttl_secs.saturating_mul(1_000_000_000));

    let value = EnforcePidValue {
        action,
        reserved: [0; 7],
        expires_at_ns,
    };

    let map_path = resolve_enforce_map_path()
        .context("could not resolve pinned enforce_pid_actions map path")?;
    let c_map_path = CString::new(map_path.to_string_lossy().as_bytes())
        .context("invalid map path")?;
    let map_fd = unsafe { bpf_obj_get(c_map_path.as_ptr()) };
    if map_fd < 0 {
        anyhow::bail!("failed to open map {}: fd={}", map_path.display(), map_fd);
    }

    let rc = unsafe {
        bpf_map_update_elem(
            map_fd,
            (&pid as *const u32).cast::<c_void>(),
            (&value as *const EnforcePidValue).cast::<c_void>(),
            0,
        )
    };
    unsafe { close(map_fd) };
    if rc != 0 {
        anyhow::bail!("failed to update enforce map: rc={}", rc);
    }
    Ok(())
}

fn monotonic_ns_now() -> u64 {
    let mut ts = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts as *mut timespec) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

impl KernelIpcHandler for LinuxKernelIpc {
    fn listen_for_events(&self) -> Result<()> {
        if strict_kernel_ipc_schema_enabled() && !self.schema_ok.load(Ordering::Relaxed) {
            anyhow::bail!("kernel IPC schema contract failed on Linux");
        }
        // Events are consumed by the ringbuffer worker in this module.
        Ok(())
    }

    fn send_response(&self, response: ScanResponse) -> Result<()> {
        // Linux enforcement response plumbing is handled at application level.
        log::debug!(
            "Sending Linux response: RequestId={}, Decision={:?}",
            response.request_id,
            response.decision
        );
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
}

async fn scan_async(req: ScanRequest, in_progress: Arc<Mutex<HashMap<PathBuf, Instant>>>) {
    {
        let mut guard = in_progress.lock().await;
        guard.retain(|_, started| started.elapsed() < Duration::from_secs(60));
        if guard.contains_key(&req.path) {
            return;
        }
        guard.insert(req.path.clone(), Instant::now());
    }

    let jitter_ms = match req.priority {
        ScanPriority::High => 10,
        ScanPriority::Low => 50,
    };
    tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
    log::debug!("queued async Linux scan: {}", req.path.display());
}

fn validate_schema_contract() -> bool {
    if let Some(expected) = expected_kernel_ipc_schema() {
        if let Err(err) = ensure_kernel_ipc_schema_compatible(expected) {
            log::error!("Linux kernel IPC schema mismatch: {}", err);
            return false;
        }
    } else if let Err(err) = ensure_kernel_ipc_schema_compatible(KERNEL_IPC_SCHEMA_VERSION) {
        log::error!("Linux kernel IPC schema validation failed: {}", err);
        return false;
    }
    true
}

fn run_ringbuffer_consumer(
    monitor: &KernelEventMonitor,
    event_seen: &Arc<AtomicBool>,
    strict_schema: bool,
    kernel_only_mode: bool,
) -> Result<()> {
    let object_path = resolve_bpf_object_path()
        .context("could not locate eBPF object file for Linux ringbuffer ingestion")?;
    tracing::info!("loading Linux eBPF object: {}", object_path.display());

    let c_path = CString::new(object_path.to_string_lossy().as_bytes())
        .context("invalid eBPF object path")?;
    let object = unsafe { bpf_object__open_file(c_path.as_ptr(), std::ptr::null()) };
    if object.is_null() || unsafe { libbpf_get_error(object.cast()) } != 0 {
        anyhow::bail!("failed to open eBPF object {}", object_path.display());
    }
    let _object_guard = BpfObjectGuard(object);

    let load_rc = unsafe { bpf_object__load(object) };
    if load_rc != 0 {
        anyhow::bail!("failed to load eBPF object into kernel: rc={}", load_rc);
    }

    let mut links: Vec<BpfLinkGuard> = Vec::new();
    let mut program: *mut bpf_program = std::ptr::null_mut();
    loop {
        program = unsafe { bpf_object__next_program(object, program) };
        if program.is_null() {
            break;
        }
        if unsafe { !bpf_program__autoload(program) } {
            continue;
        }
        let prog_name = unsafe {
            let ptr = bpf_program__name(program);
            if ptr.is_null() {
                "<unknown>".to_string()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().to_string()
            }
        };
        let link = unsafe { bpf_program__attach(program) };
        if link.is_null() || unsafe { libbpf_get_error(link.cast()) } != 0 {
            tracing::warn!("failed to attach eBPF program {}", prog_name);
            continue;
        }
        tracing::info!("attached eBPF program: {}", prog_name);
        links.push(BpfLinkGuard(link));
    }
    if links.is_empty() {
        anyhow::bail!("no eBPF programs could be attached");
    }

    let events_name = CString::new("events").expect("static string is valid C string");
    let events_map_fd = unsafe { bpf_object__find_map_fd_by_name(object, events_name.as_ptr()) };
    if events_map_fd < 0 {
        anyhow::bail!("ringbuffer map 'events' was not found in eBPF object");
    }

    let callback_ctx = Box::new(RingbufferCallbackCtx {
        monitor: monitor.clone(),
        event_seen: event_seen.clone(),
        strict_schema,
        kernel_only_mode,
    });
    let callback_ctx_ptr = Box::into_raw(callback_ctx);
    let ringbuf = unsafe {
        ring_buffer__new(
            events_map_fd,
            Some(handle_ringbuf_sample),
            callback_ctx_ptr.cast(),
            std::ptr::null(),
        )
    };
    if ringbuf.is_null() || unsafe { libbpf_get_error(ringbuf.cast()) } != 0 {
        unsafe {
            drop(Box::from_raw(callback_ctx_ptr));
        }
        anyhow::bail!("failed to create ringbuffer consumer");
    }
    let _ringbuf_guard = RingBufferGuard(ringbuf, callback_ctx_ptr);

    loop {
        let rc = unsafe { ring_buffer__poll(ringbuf, 250) };
        if rc < 0 {
            tracing::warn!("ringbuffer poll error: rc={}", rc);
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn resolve_bpf_object_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("AV_EBPF_OBJECT_PATH") {
        let candidate = PathBuf::from(explicit);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    let candidates = [
        "av-kernel-linux/ebpf/out/monitor.bpf.o",
        "av-kernel-linux/ebpf/out/lsm_file_monitor.o",
        "../av-kernel-linux/ebpf/out/monitor.bpf.o",
        "../av-kernel-linux/ebpf/out/lsm_file_monitor.o",
        "/opt/cybershield/lib/monitor.bpf.o",
        "/opt/cybershield/lib/lsm_file_monitor.o",
    ];
    candidates
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .map(Path::to_path_buf)
}

fn resolve_enforce_map_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("AV_EBPF_ENFORCE_MAP_PATH") {
        let candidate = PathBuf::from(explicit);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    let candidates = [
        "/sys/fs/bpf/enforce_pid_actions",
        "/sys/fs/bpf/monitor.bpf/enforce_pid_actions",
        "/sys/fs/bpf/monitor/enforce_pid_actions",
    ];
    candidates
        .iter()
        .map(Path::new)
        .find(|path| path.exists())
        .map(Path::to_path_buf)
}

struct BpfObjectGuard(*mut bpf_object);
impl Drop for BpfObjectGuard {
    fn drop(&mut self) {
        unsafe { bpf_object__close(self.0) };
    }
}

struct BpfLinkGuard(*mut bpf_link);
impl Drop for BpfLinkGuard {
    fn drop(&mut self) {
        unsafe { bpf_link__destroy(self.0) };
    }
}

struct RingBufferGuard(*mut ring_buffer, *mut RingbufferCallbackCtx);
impl Drop for RingBufferGuard {
    fn drop(&mut self) {
        unsafe {
            ring_buffer__free(self.0);
            drop(Box::from_raw(self.1));
        }
    }
}

struct RingbufferCallbackCtx {
    monitor: KernelEventMonitor,
    event_seen: Arc<AtomicBool>,
    strict_schema: bool,
    kernel_only_mode: bool,
}

unsafe extern "C" fn handle_ringbuf_sample(
    ctx: *mut c_void,
    data: *mut c_void,
    size: c_ulong,
) -> c_int {
    if ctx.is_null() || data.is_null() || size == 0 {
        return 0;
    }

    let cb = unsafe { &*(ctx as *const RingbufferCallbackCtx) };
    let payload = unsafe { std::slice::from_raw_parts(data as *const u8, size as usize) };

    let wire_event = match KernelWireEvent::from_ringbuf_frame(payload) {
        Ok(event) => event,
        Err(err) => {
            tracing::error!("invalid Linux ringbuffer frame: {}", err);
            if cb.strict_schema && cb.kernel_only_mode {
                std::process::exit(3);
            }
            return 0;
        }
    };

    if let Err(err) = ensure_schema_compatible(wire_event.schema_version) {
        tracing::error!("kernel ringbuffer schema mismatch: {}", err);
        if cb.strict_schema && cb.kernel_only_mode {
            std::process::exit(3);
        }
        return 0;
    }

    cb.event_seen.store(true, Ordering::Relaxed);
    cb.monitor.push_event(wire_event.into_parsed_event());
    0
}

#[repr(C)]
struct bpf_object {
    _private: [u8; 0],
}

#[repr(C)]
struct bpf_program {
    _private: [u8; 0],
}

#[repr(C)]
struct bpf_link {
    _private: [u8; 0],
}

#[repr(C)]
struct ring_buffer {
    _private: [u8; 0],
}

#[repr(C)]
struct timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

const CLOCK_MONOTONIC: c_int = 1;

#[link(name = "bpf")]
unsafe extern "C" {
    fn bpf_object__open_file(path: *const c_char, opts: *const c_void) -> *mut bpf_object;
    fn bpf_object__load(obj: *mut bpf_object) -> c_int;
    fn bpf_object__close(obj: *mut bpf_object);
    fn bpf_object__next_program(obj: *mut bpf_object, prev: *mut bpf_program) -> *mut bpf_program;
    fn bpf_program__autoload(prog: *mut bpf_program) -> bool;
    fn bpf_program__name(prog: *mut bpf_program) -> *const c_char;
    fn bpf_program__attach(prog: *mut bpf_program) -> *mut bpf_link;
    fn bpf_link__destroy(link: *mut bpf_link);
    fn bpf_object__find_map_fd_by_name(obj: *mut bpf_object, name: *const c_char) -> c_int;
    fn ring_buffer__new(
        map_fd: c_int,
        sample_cb: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, c_ulong) -> c_int>,
        ctx: *mut c_void,
        opts: *const c_void,
    ) -> *mut ring_buffer;
    fn ring_buffer__poll(rb: *mut ring_buffer, timeout_ms: c_int) -> c_int;
    fn ring_buffer__free(rb: *mut ring_buffer);
    fn libbpf_get_error(ptr: *const c_void) -> c_long;
    fn bpf_obj_get(path: *const c_char) -> c_int;
    fn bpf_map_update_elem(fd: c_int, key: *const c_void, value: *const c_void, flags: u64)
        -> c_int;
    fn close(fd: c_int) -> c_int;
    fn clock_gettime(clk_id: c_int, tp: *mut timespec) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_kernel_ipc_creation() {
        let ipc = LinuxKernelIpc::new();
        assert!(ipc.is_connected());
    }
}
