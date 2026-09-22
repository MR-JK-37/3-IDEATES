use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub static FILES_SCANNED: AtomicU64 = AtomicU64::new(0);
pub static EVENTS_CAPTURED: AtomicU64 = AtomicU64::new(0);
pub static THREATS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static THREATS_TODAY: AtomicU64 = AtomicU64::new(0);
pub static AV_CPU_TENTHS: AtomicU64 = AtomicU64::new(0);
pub static AV_RAM_MB: AtomicU64 = AtomicU64::new(0);
pub static ESTIMATED_TARGET_FILES: AtomicU64 = AtomicU64::new(0);

pub static FILE_MONITOR_ACTIVE: AtomicBool = AtomicBool::new(false);
pub static PROCESS_MONITOR_ACTIVE: AtomicBool = AtomicBool::new(false);
pub static NETWORK_MONITOR_ACTIVE: AtomicBool = AtomicBool::new(false);
pub static DRIVE_MONITOR_ACTIVE: AtomicBool = AtomicBool::new(false);

pub static FILE_MONITOR_EVENTS: AtomicU64 = AtomicU64::new(0);
pub static PROCESS_MONITOR_EVENTS: AtomicU64 = AtomicU64::new(0);
pub static NETWORK_MONITOR_EVENTS: AtomicU64 = AtomicU64::new(0);
pub static DRIVE_MONITOR_EVENTS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize)]
pub struct MonitorStatus {
    pub name: String,
    pub active: bool,
    pub events_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveStatsSnapshot {
    pub files_per_sec: f64,
    pub events_per_sec: f64,
    pub total_scanned: u64,
    pub threats_today: u64,
    pub threats_total: u64,
    pub monitors_active: Vec<MonitorStatus>,
    pub av_cpu: f64,
    pub av_ram_mb: u64,
    pub scan_progress_percent: f64,
    pub uptime_secs: u64,
    pub last_scan_file: String,
}

#[derive(Debug)]
pub struct LiveStatsState {
    start: Instant,
    last_files_total: u64,
    last_events_total: u64,
    last_scan_file: Arc<Mutex<String>>,
}

impl Default for LiveStatsState {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            last_files_total: 0,
            last_events_total: 0,
            last_scan_file: Arc::new(Mutex::new(String::new())),
        }
    }
}

impl LiveStatsState {
    pub fn update_last_scan_file(&self, path: &str) {
        if let Ok(mut guard) = self.last_scan_file.lock() {
            *guard = path.to_string();
        }
    }

    pub fn snapshot(&mut self, cpu_usage: f64, memory_mb: u64) -> LiveStatsSnapshot {
        let total_files = FILES_SCANNED.load(Ordering::Relaxed);
        let total_events = EVENTS_CAPTURED.load(Ordering::Relaxed);

        let files_per_sec = total_files.saturating_sub(self.last_files_total) as f64;
        let events_per_sec = total_events.saturating_sub(self.last_events_total) as f64;
        self.last_files_total = total_files;
        self.last_events_total = total_events;

        let last_scan_file = self
            .last_scan_file
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let estimated_targets = ESTIMATED_TARGET_FILES.load(Ordering::Relaxed);
        let scan_progress_percent = if estimated_targets > 0 {
            ((total_files as f64 / estimated_targets as f64) * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };

        LiveStatsSnapshot {
            files_per_sec,
            events_per_sec,
            total_scanned: total_files,
            threats_today: THREATS_TODAY.load(Ordering::Relaxed),
            threats_total: THREATS_TOTAL.load(Ordering::Relaxed),
            monitors_active: vec![
                MonitorStatus {
                    name: "File Monitor".to_string(),
                    active: FILE_MONITOR_ACTIVE.load(Ordering::Relaxed),
                    events_count: FILE_MONITOR_EVENTS.load(Ordering::Relaxed),
                },
                MonitorStatus {
                    name: "Process Monitor".to_string(),
                    active: PROCESS_MONITOR_ACTIVE.load(Ordering::Relaxed),
                    events_count: PROCESS_MONITOR_EVENTS.load(Ordering::Relaxed),
                },
                MonitorStatus {
                    name: "Network Monitor".to_string(),
                    active: NETWORK_MONITOR_ACTIVE.load(Ordering::Relaxed),
                    events_count: NETWORK_MONITOR_EVENTS.load(Ordering::Relaxed),
                },
                MonitorStatus {
                    name: "Drive Monitor".to_string(),
                    active: DRIVE_MONITOR_ACTIVE.load(Ordering::Relaxed),
                    events_count: DRIVE_MONITOR_EVENTS.load(Ordering::Relaxed),
                },
            ],
            av_cpu: cpu_usage,
            av_ram_mb: memory_mb,
            scan_progress_percent,
            uptime_secs: self.start.elapsed().as_secs(),
            last_scan_file,
        }
    }
}

pub fn record_scan(path: &str, state: &LiveStatsState) {
    FILES_SCANNED.fetch_add(1, Ordering::Relaxed);
    FILE_MONITOR_EVENTS.fetch_add(1, Ordering::Relaxed);
    state.update_last_scan_file(path);
}

pub fn record_event() {
    EVENTS_CAPTURED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_process_event() {
    EVENTS_CAPTURED.fetch_add(1, Ordering::Relaxed);
    PROCESS_MONITOR_EVENTS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_network_event() {
    EVENTS_CAPTURED.fetch_add(1, Ordering::Relaxed);
    NETWORK_MONITOR_EVENTS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_drive_event() {
    EVENTS_CAPTURED.fetch_add(1, Ordering::Relaxed);
    DRIVE_MONITOR_EVENTS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_threat() {
    THREATS_TOTAL.fetch_add(1, Ordering::Relaxed);
    THREATS_TODAY.fetch_add(1, Ordering::Relaxed);
}

pub fn set_resource_usage(cpu_percent: f64, memory_mb: u64) {
    let cpu_tenths = (cpu_percent.max(0.0) * 10.0).round() as u64;
    AV_CPU_TENTHS.store(cpu_tenths, Ordering::Relaxed);
    AV_RAM_MB.store(memory_mb, Ordering::Relaxed);
}

pub fn set_estimated_target_files(count: u64) {
    ESTIMATED_TARGET_FILES.store(count, Ordering::Relaxed);
}
