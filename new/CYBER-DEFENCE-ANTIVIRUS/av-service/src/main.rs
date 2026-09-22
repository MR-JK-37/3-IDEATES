use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock, Semaphore};
use tokio::time::{sleep, Duration, Instant as TokioInstant};
use uuid::Uuid;

mod api;
mod drive_scanner;
mod engines;
mod fp_filter;
mod hashdb;
mod kernel_comm;
mod kernel_events;
#[cfg_attr(not(target_os = "windows"), allow(dead_code, unused_imports))]
mod kernel_ipc;
mod network_threat_detector;
mod policy_pipeline;
mod stats;
mod updater;

use api::{
    create_router, load_settings, AlertSeverity, AppState, ProcessBlocklist, RealtimeEvent,
    ScanJob, ScanSource, ThreatAlert, ThreatEntry,
};
use engines::{scan_with_all_engines, MultiEngineResult};
use hashdb::init_db;
use kernel_comm::{KernelEventMonitor, ParsedEvent};
use kernel_events::{
    normalize_kernel_event, KernelEventKind, KernelPolicyAuditRecord, PolicyDecision,
    KERNEL_EVENT_SCHEMA_VERSION,
};
#[cfg(target_os = "linux")]
use kernel_ipc::linux::spawn_ringbuffer_consumer;
#[cfg(target_os = "linux")]
use kernel_ipc::linux::set_pid_enforcement_action;
use network_threat_detector::{ConnectionVerdict, NetworkThreatDetector};
use policy_pipeline::{append_policy_audit, evaluate_kernel_policy};
use stats::{
    record_drive_event, record_network_event, record_process_event, record_scan, record_threat,
    set_estimated_target_files, set_resource_usage, LiveStatsState, DRIVE_MONITOR_ACTIVE,
    FILE_MONITOR_ACTIVE,
    NETWORK_MONITOR_ACTIVE, PROCESS_MONITOR_ACTIVE,
};

const SCAN_WORKERS: usize = 4;
const IN_PROGRESS_TTL: Duration = Duration::from_secs(60);
const CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const CACHE_CAPACITY: usize = 10_000;
const SCAN_TIMEOUT: Duration = Duration::from_secs(30);
const WATCH_MAX_FILES: usize = 600;
const WATCH_MAX_DEPTH: usize = 3;
const THREAT_HISTORY_LIMIT: usize = 2000;
const LIVE_PROCESS_SCAN_INTERVAL: Duration = Duration::from_secs(30);
const LIVE_NETWORK_SCAN_INTERVAL: Duration = Duration::from_secs(60);
const ALERT_GROUP_DELAY: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy)]
enum KernelMonitorMode {
    Auto,
    KernelOnly,
    ProcfsOnly,
}

impl KernelMonitorMode {
    fn from_env() -> Self {
        match std::env::var("AV_KERNEL_MONITOR_MODE")
            .unwrap_or_else(|_| "auto".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "kernel" | "kernel_only" => Self::KernelOnly,
            "procfs" | "fallback" | "userspace" => Self::ProcfsOnly,
            _ => Self::Auto,
        }
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct CacheKey {
    path: String,
    size: u64,
    modified_epoch_secs: u64,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    result: MultiEngineResult,
    scanned_at: Instant,
}

#[derive(Default)]
struct ScanCache {
    entries: HashMap<CacheKey, CacheEntry>,
    lru: VecDeque<CacheKey>,
}

impl ScanCache {
    fn get(&mut self, key: &CacheKey) -> Option<MultiEngineResult> {
        if let Some(result) = self
            .entries
            .get(key)
            .filter(|entry| entry.scanned_at.elapsed() <= CACHE_TTL)
            .map(|entry| entry.result.clone())
        {
            self.touch_lru(key.clone());
            return Some(result);
        }
        self.entries.remove(key);
        None
    }

    fn put(&mut self, key: CacheKey, result: MultiEngineResult) {
        self.entries.insert(
            key.clone(),
            CacheEntry {
                result,
                scanned_at: Instant::now(),
            },
        );
        self.touch_lru(key);
        self.evict_if_needed();
    }

    fn touch_lru(&mut self, key: CacheKey) {
        if let Some(pos) = self.lru.iter().position(|k| k == &key) {
            self.lru.remove(pos);
        }
        self.lru.push_back(key);
    }

    fn evict_if_needed(&mut self) {
        while self.entries.len() > CACHE_CAPACITY {
            if let Some(old_key) = self.lru.pop_front() {
                self.entries.remove(&old_key);
            } else {
                break;
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    std::panic::set_hook(Box::new(|panic_info| {
        tracing::error!("panic in av-service: {}", panic_info);
        let backtrace = std::backtrace::Backtrace::capture();
        tracing::error!("backtrace: {}", backtrace);
    }));

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(true)
        .with_thread_ids(true)
        .init();

    tracing::info!("av-service starting");
    tracing::info!(
        "kernel event schema version: {}",
        KERNEL_EVENT_SCHEMA_VERSION
    );

    if let Some(expected) = std::env::var("AV_KERNEL_SCHEMA_VERSION_EXPECTED")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
    {
        if expected != KERNEL_EVENT_SCHEMA_VERSION {
            anyhow::bail!(
                "service schema expectation mismatch: expected {}, service supports {}",
                expected,
                KERNEL_EVENT_SCHEMA_VERSION
            );
        }
    }

    let db_path = std::env::var("HASH_DB_PATH").unwrap_or_else(|_| "hash_db.sqlite".to_string());
    init_db(&db_path)?;
    tracing::info!("Hash database initialized at {}", db_path);

    #[cfg(target_os = "windows")]
    {
        let mut kernel_ipc = kernel_ipc::PlatformKernelIpc::new();
        if let Err(e) = kernel_ipc.connect() {
            tracing::warn!("Failed to connect to minifilter driver: {}", e);
        } else {
            tracing::info!("Connected to Windows minifilter driver");
        }
    }

    let kernel_mode = KernelMonitorMode::from_env();
    tracing::info!("kernel monitor mode: {:?}", kernel_mode);

    let (tx, mut rx) = mpsc::channel::<ScanJob>(512);
    let (realtime_events, _) = broadcast::channel::<RealtimeEvent>(512);
    let (alert_tx, alert_rx) = mpsc::channel::<ThreatAlert>(1024);

    let threats = Arc::new(tokio::sync::Mutex::new(Vec::<ThreatEntry>::new()));
    let quarantine_dir = std::env::var("QUARANTINE_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        format!("{}/.local/share/cybershield/quarantine", home)
    });

    let settings_path = std::env::var("AV_SETTINGS_PATH")
        .unwrap_or_else(|_| "config/runtime-settings.json".to_string());
    let settings = Arc::new(tokio::sync::RwLock::new(load_settings(&settings_path)));
    let pending_alerts = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let monitored_processes = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let allowlist = Arc::new(RwLock::new(Vec::<String>::new()));
    let live_stats = Arc::new(Mutex::new(LiveStatsState::default()));

    let app_state = Arc::new(AppState {
        scan_tx: tx.clone(),
        threats: threats.clone(),
        quarantine_dir: quarantine_dir.clone(),
        settings: settings.clone(),
        settings_path: settings_path.clone(),
        realtime_events: realtime_events.clone(),
        process_blocks: Arc::new(RwLock::new(ProcessBlocklist::default())),
        pending_alerts: pending_alerts.clone(),
        monitored_processes: monitored_processes.clone(),
        allowlist: allowlist.clone(),
        live_stats: live_stats.clone(),
    });

    let network_detector = Arc::new(NetworkThreatDetector::new().await?);
    let (kernel_monitor, mut kernel_event_rx) = KernelEventMonitor::new();

    tokio::spawn(async {
        updater::start_signature_updater().await;
    });

    {
        let pending_alerts_worker = pending_alerts.clone();
        let events_worker = realtime_events.clone();
        tokio::spawn(async move {
            run_alert_manager(alert_rx, pending_alerts_worker, events_worker).await;
        });
    }

    let kernel_socket_seen = Arc::new(AtomicBool::new(false));
    let strict_kernel_schema =
        std::env::var("AV_KERNEL_STRICT_SCHEMA").unwrap_or_else(|_| "true".to_string()) != "false";
    let kernel_only_mode = matches!(kernel_mode, KernelMonitorMode::KernelOnly);
    #[cfg(target_os = "linux")]
    {
        tracing::info!("starting Linux eBPF ringbuffer ingestion");
        drop(spawn_ringbuffer_consumer(
            kernel_monitor.clone(),
            kernel_socket_seen.clone(),
            strict_kernel_schema,
            kernel_only_mode,
        ));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = strict_kernel_schema;
        let _ = kernel_only_mode;
    }

    if matches!(kernel_mode, KernelMonitorMode::Auto | KernelMonitorMode::ProcfsOnly) {
        let kernel_monitor_bg = kernel_monitor.clone();
        tokio::spawn(async move {
            let _ = kernel_monitor_bg.start_procfs_fallback().await;
        });
    } else {
        tracing::info!("procfs fallback disabled because AV_KERNEL_MONITOR_MODE=kernel");
        let startup_timeout_secs = std::env::var("AV_KERNEL_EVENT_STARTUP_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(20);
        let kernel_socket_seen_guard = kernel_socket_seen.clone();
        tokio::spawn(async move {
            sleep(Duration::from_secs(startup_timeout_secs)).await;
            if !kernel_socket_seen_guard.load(Ordering::Relaxed) {
                tracing::error!(
                    "kernel-only mode requires real kernel events, but no ringbuffer event was received within {}s. Exiting.",
                    startup_timeout_secs
                );
                std::process::exit(2);
            }
        });
    }

    if !matches!(kernel_mode, KernelMonitorMode::KernelOnly) {
        // Real-time fallback watcher:
        // If kernel events are unavailable, monitor configured directories for file changes.
        let watch_paths = load_watch_paths();
        let tx_watch = tx.clone();
        let settings_watch = settings.clone();
        tokio::spawn(async move {
            let mut known: HashMap<String, u64> = HashMap::new();
            let mut initialized = false;
            loop {
                if !settings_watch.read().await.real_time_protection {
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }

                let paths = watch_paths.clone();
                let snapshot = tokio::task::spawn_blocking(move || {
                    collect_watch_snapshot(&paths, WATCH_MAX_FILES, WATCH_MAX_DEPTH)
                })
                .await
                .unwrap_or_default();

                let mut current = HashMap::new();
                for (path, mtime) in snapshot {
                    current.insert(path.clone(), mtime);
                    if initialized {
                        let changed = known.get(&path).map(|prev| *prev != mtime).unwrap_or(true);
                        if changed {
                            let _ = tx_watch.try_send(ScanJob {
                                path,
                                source: ScanSource::Realtime,
                            });
                        }
                    }
                }
                set_estimated_target_files(current.len() as u64);

                if !initialized {
                    initialized = true;
                }
                known = current;
                sleep(Duration::from_secs(2)).await;
            }
        });
    } else {
        tracing::info!("userspace fallback watcher disabled because AV_KERNEL_MONITOR_MODE=kernel");
    }

    let vt_key = std::env::var("VT_API_KEY")
        .ok()
        .or_else(|| std::env::var("VIRUSTOTAL_API_KEY").ok());
    let yara_rules = std::env::var("YARA_RULES").ok();

    {
        let tx_process = tx.clone();
        let settings_process = settings.clone();
        tokio::spawn(async move {
            PROCESS_MONITOR_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
            live_process_scanner(tx_process, settings_process).await;
        });
    }

    {
        let threats_network = threats.clone();
        let events_network = realtime_events.clone();
        let alert_tx_network = alert_tx.clone();
        let settings_network = settings.clone();
        tokio::spawn(async move {
            NETWORK_MONITOR_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
            live_network_scanner(
                threats_network,
                events_network,
                alert_tx_network,
                settings_network,
            )
            .await;
        });
    }

    {
        let tx_drive = tx.clone();
        tokio::spawn(async move {
            DRIVE_MONITOR_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
            drive_scanner::watch_drive_mounts(tx_drive).await;
        });
    }

    {
        let tx_kernel = tx.clone();
        let settings_kernel = settings.clone();
        let detector_kernel = network_detector.clone();
        let threats_kernel = threats.clone();
        let events_kernel = realtime_events.clone();
        let alert_tx_kernel = alert_tx.clone();
        let quarantine_dir_kernel = Arc::new(quarantine_dir.clone());
        tokio::spawn(async move {
            let net_seen = Arc::new(Mutex::new(HashSet::<String>::new()));
            while let Some(event) = kernel_event_rx.recv().await {
                handle_kernel_event(
                    event,
                    tx_kernel.clone(),
                    settings_kernel.clone(),
                    detector_kernel.clone(),
                    threats_kernel.clone(),
                    events_kernel.clone(),
                    alert_tx_kernel.clone(),
                    quarantine_dir_kernel.clone(),
                    net_seen.clone(),
                )
                .await;
            }
        });
    }

    let threats_worker = threats.clone();
    let settings_worker = settings.clone();
    let events_worker = realtime_events.clone();
    let quarantine_dir_worker = Arc::new(quarantine_dir.clone());
    let scan_throttle_ms = Arc::new(RwLock::new(10_u64));
    let throttle_monitor = scan_throttle_ms.clone();
    let scan_semaphore = Arc::new(Semaphore::new(SCAN_WORKERS));
    let in_progress = Arc::new(Mutex::new(HashMap::<String, Instant>::new()));
    let scan_cache = Arc::new(Mutex::new(ScanCache::default()));
    let vt_key = Arc::new(vt_key);
    let yara_rules = Arc::new(yara_rules);
    let live_stats_worker = live_stats.clone();

    tokio::spawn(async move {
        monitor_self_resources(throttle_monitor).await;
    });

    tokio::spawn(async move {
        while let Some(job) = rx.recv().await {
            let permit = match scan_semaphore.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => break,
            };

            let settings_worker = settings_worker.clone();
            let scan_throttle_ms = scan_throttle_ms.clone();
            let in_progress = in_progress.clone();
            let scan_cache = scan_cache.clone();
            let threats_worker = threats_worker.clone();
            let events_worker = events_worker.clone();
            let quarantine_dir_worker = quarantine_dir_worker.clone();
            let vt_key = vt_key.clone();
            let yara_rules = yara_rules.clone();
            let pending_alerts_worker = pending_alerts.clone();
            let allowlist_worker = allowlist.clone();
            let alert_tx_worker = alert_tx.clone();
            let live_stats = live_stats_worker.clone();

            tokio::spawn(async move {
                let _permit = permit;
                process_scan_job(
                    job,
                    settings_worker,
                    scan_throttle_ms,
                    in_progress,
                    scan_cache,
                    threats_worker,
                    events_worker,
                    quarantine_dir_worker,
                    vt_key,
                    yara_rules,
                    pending_alerts_worker,
                    allowlist_worker,
                    alert_tx_worker,
                    live_stats,
                )
                .await;
            });
        }
    });

    let api_port: u16 = std::env::var("AV_SERVICE_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3001);
    let listener = TcpListener::bind(format!("0.0.0.0:{}", api_port)).await?;
    tracing::info!("REST API listening on port {}", api_port);

    let router = create_router(app_state);
    tokio::spawn(async move { axum::serve(listener, router).await });

    tokio::signal::ctrl_c().await?;
    tracing::info!("av-service shutting down");

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn process_scan_job(
    job: ScanJob,
    settings: Arc<tokio::sync::RwLock<api::ServiceSettings>>,
    scan_throttle_ms: Arc<RwLock<u64>>,
    in_progress: Arc<Mutex<HashMap<String, Instant>>>,
    scan_cache: Arc<Mutex<ScanCache>>,
    threats: Arc<tokio::sync::Mutex<Vec<ThreatEntry>>>,
    events: broadcast::Sender<RealtimeEvent>,
    quarantine_dir: Arc<String>,
    vt_key: Arc<Option<String>>,
    yara_rules: Arc<Option<String>>,
    pending_alerts: Arc<Mutex<HashMap<String, ThreatAlert>>>,
    allowlist: Arc<RwLock<Vec<String>>>,
    alert_tx: mpsc::Sender<ThreatAlert>,
    live_stats: Arc<Mutex<LiveStatsState>>,
) {
    let realtime_enabled = settings.read().await.real_time_protection;
    if matches!(job.source, ScanSource::Realtime) && !realtime_enabled {
        tracing::debug!(
            "Realtime scan ignored while protection is off: {}",
            job.path
        );
        return;
    }

    let path_str = job.path.trim().to_string();
    FILE_MONITOR_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
    let path = Path::new(&path_str);
    if !path.exists() {
        tracing::warn!("Scan target does not exist: {}", path_str);
        return;
    }
    {
        let allow = allowlist.read().await;
        if allow.iter().any(|p| p == &path_str) {
            tracing::info!("Skipping allowlisted path: {}", path_str);
            return;
        }
    }
    if matches!(job.source, ScanSource::Realtime) && !is_realtime_priority_path(path) {
        return;
    }

    {
        let mut guard = in_progress.lock().await;
        guard.retain(|_, started_at| started_at.elapsed() <= IN_PROGRESS_TTL);
        if let Some(started_at) = guard.get(&path_str) {
            if started_at.elapsed() <= IN_PROGRESS_TTL {
                return;
            }
        }
        guard.insert(path_str.clone(), Instant::now());
    }

    let delay = *scan_throttle_ms.read().await;
    if delay > 0 {
        sleep(Duration::from_millis(delay)).await;
    }

    let metadata = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("Cannot read metadata {}: {}", path_str, e);
            return;
        }
    };
    let cache_key = cache_key_for_path(path_str.clone(), &metadata);

    let cached_result = {
        let mut cache = scan_cache.lock().await;
        cache.get(&cache_key)
    };

    let multi_result = if let Some(result) = cached_result {
        tracing::debug!("cache hit for {}", path_str);
        result
    } else {
        let file_hash = match hash_file_streaming(path) {
            Ok(hash) => hash,
            Err(e) => {
                tracing::warn!("Cannot read file {}: {}", path_str, e);
                return;
            }
        };

        let vt_key_ref = vt_key.as_deref();
        let yara_rules_ref = yara_rules.as_deref();

        let scan_future = scan_with_all_engines(path, &file_hash, vt_key_ref, yara_rules_ref);
        let result = match tokio::time::timeout(SCAN_TIMEOUT, scan_future).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::warn!("Scan error for {}: {}", path_str, e);
                return;
            }
            Err(_) => {
                tracing::warn!("Scan timeout for {}", path_str);
                return;
            }
        };

        {
            let mut cache = scan_cache.lock().await;
            cache.put(cache_key, result.clone());
        }
        result
    };

    tracing::info!(
        "Scan completed for {}: verdict={:?}, threats={}",
        path_str,
        multi_result.final_verdict,
        multi_result.detections.len()
    );
    {
        let guard = live_stats.lock().await;
        record_scan(&path_str, &guard);
    }

    if matches!(multi_result.final_verdict, engines::ThreatLevel::Clean) {
        return;
    }

    for detection in &multi_result.detections {
        if !should_emit_detection(detection, multi_result.final_verdict.clone()) {
            continue;
        }
        if fp_filter::should_suppress_detection(&path_str, detection) {
            tracing::info!(
                "Suppressed likely false-positive detection for non-executable file {} [{}:{}]",
                path_str,
                detection.engine,
                detection.threat_name
            );
            continue;
        }
        tracing::warn!(
            "  [{}] {} - Confidence: {:.2}",
            detection.engine,
            detection.threat_name,
            detection.confidence
        );
        emit_threat(
            &path_str,
            detection,
            &threats,
            &events,
            &pending_alerts,
            &quarantine_dir,
            settings.read().await.quarantine_enabled,
            &alert_tx,
        )
        .await;
    }
}

fn should_emit_detection(
    detection: &engines::DetectionResult,
    final_verdict: engines::ThreatLevel,
) -> bool {
    match final_verdict {
        engines::ThreatLevel::Malicious => {
            detection.level == engines::ThreatLevel::Malicious
                || (detection.level == engines::ThreatLevel::Suspicious
                    && detection.confidence >= 0.90)
        }
        engines::ThreatLevel::Suspicious => {
            detection.level == engines::ThreatLevel::Suspicious && detection.confidence >= 0.75
        }
        engines::ThreatLevel::Clean => false,
    }
}

fn cache_key_for_path(path: String, metadata: &std::fs::Metadata) -> CacheKey {
    let modified_epoch_secs = metadata
        .modified()
        .ok()
        .and_then(|ts| ts.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });

    CacheKey {
        path,
        size: metadata.len(),
        modified_epoch_secs,
    }
}

async fn emit_threat(
    path_str: &str,
    detection: &engines::DetectionResult,
    threats: &Arc<tokio::sync::Mutex<Vec<ThreatEntry>>>,
    events: &broadcast::Sender<RealtimeEvent>,
    _pending_alerts: &Arc<Mutex<HashMap<String, ThreatAlert>>>,
    quarantine_dir: &str,
    quarantine_enabled: bool,
    alert_tx: &mpsc::Sender<ThreatAlert>,
) {
    let (severity, action, alert_severity) = match detection.level {
        engines::ThreatLevel::Malicious => {
            ("Critical", "PendingUserDecision", AlertSeverity::Critical)
        }
        engines::ThreatLevel::Suspicious => {
            ("Medium", "PendingUserDecision", AlertSeverity::Medium)
        }
        engines::ThreatLevel::Clean => return,
    };

    let entry = ThreatEntry {
        id: Uuid::new_v4().to_string(),
        name: detection.threat_name.clone(),
        path: path_str.to_string(),
        severity: severity.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        engine: detection.engine.clone(),
        action: action.to_string(),
        details: Some(friendly_explanation_for_detection(path_str, detection)),
    };

    {
        let mut t = threats.lock().await;
        let duplicate = t.iter().any(|existing| {
            existing.path == entry.path
                && existing.name == entry.name
                && existing.engine == entry.engine
                && existing.action == "PendingUserDecision"
        });
        if duplicate {
            tracing::info!(
                "Skipping duplicate threat event for {} [{}:{}]",
                entry.path,
                entry.engine,
                entry.name
            );
            return;
        }
        t.insert(0, entry.clone());
        if t.len() > THREAT_HISTORY_LIMIT {
            t.truncate(THREAT_HISTORY_LIMIT);
        }
    }

    let _ = events.send(RealtimeEvent::ThreatDetected(entry));
    record_threat();

    let file_name = Path::new(path_str)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    let alert = ThreatAlert {
        id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().timestamp(),
        file_path: path_str.to_string(),
        process_name: file_name,
        pid: 0,
        threat_type: format!("{:?}", detection.level),
        threat_name: detection.threat_name.clone(),
        severity: alert_severity,
        detection_engines: vec![detection.engine.clone()],
        confidence: detection.confidence,
        ai_explanation: friendly_explanation_for_detection(path_str, detection),
    };

    // Alert delivery is centralized so we can group bursts intelligently.
    let _ = alert_tx.send(alert).await;

    if quarantine_enabled {
        tracing::info!(
            "Quarantine is enabled at {} but waiting for explicit user decision before moving file",
            quarantine_dir
        );
    }
}

async fn run_alert_manager(
    mut rx: mpsc::Receiver<ThreatAlert>,
    pending_alerts: Arc<Mutex<HashMap<String, ThreatAlert>>>,
    events: broadcast::Sender<RealtimeEvent>,
) {
    let mut grouped_queue: Vec<ThreatAlert> = Vec::new();
    let mut grouped_deadline: Option<TokioInstant> = None;
    let mut burst_started_at: Option<TokioInstant> = None;
    let mut immediate_sent_in_burst: u8 = 0;

    loop {
        if let Some(deadline) = grouped_deadline {
            tokio::select! {
                maybe_alert = rx.recv() => {
                    let Some(alert) = maybe_alert else { break; };
                    grouped_queue.push(alert);
                }
                _ = tokio::time::sleep_until(deadline) => {
                    if !grouped_queue.is_empty() {
                        let grouped = build_grouped_alert(&grouped_queue);
                        dispatch_alert(grouped, &pending_alerts, &events).await;
                        grouped_queue.clear();
                    }
                    grouped_deadline = None;
                    burst_started_at = None;
                    immediate_sent_in_burst = 0;
                }
            }
            continue;
        }

        let Some(alert) = rx.recv().await else { break };
        let now = TokioInstant::now();
        let in_existing_burst = burst_started_at
            .map(|start| now.duration_since(start) <= ALERT_GROUP_DELAY)
            .unwrap_or(false);

        if !in_existing_burst {
            burst_started_at = Some(now);
            immediate_sent_in_burst = 0;
        }

        if immediate_sent_in_burst < 2 {
            dispatch_alert(alert, &pending_alerts, &events).await;
            immediate_sent_in_burst += 1;
            continue;
        }

        grouped_queue.push(alert);
        grouped_deadline = Some(now + ALERT_GROUP_DELAY);
    }
}

async fn dispatch_alert(
    alert: ThreatAlert,
    pending_alerts: &Arc<Mutex<HashMap<String, ThreatAlert>>>,
    events: &broadcast::Sender<RealtimeEvent>,
) {
    {
        let mut pending = pending_alerts.lock().await;
        pending.insert(alert.id.clone(), alert.clone());
    }
    let _ = events.send(RealtimeEvent::ThreatAlert(alert));
}

fn build_grouped_alert(alerts: &[ThreatAlert]) -> ThreatAlert {
    let top = alerts
        .iter()
        .max_by_key(|a| severity_rank(&a.severity))
        .cloned()
        .unwrap_or_else(|| ThreatAlert {
            id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            file_path: "unknown".to_string(),
            process_name: "unknown".to_string(),
            pid: 0,
            threat_type: "Grouped".to_string(),
            threat_name: "Grouped Threat Burst".to_string(),
            severity: AlertSeverity::High,
            detection_engines: vec!["CyberShield Correlator".to_string()],
            confidence: 0.8,
            ai_explanation: "Multiple threats were detected in a short burst.".to_string(),
        });

    let names = alerts
        .iter()
        .take(4)
        .map(|a| a.threat_name.clone())
        .collect::<Vec<_>>()
        .join(", ");

    ThreatAlert {
        id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().timestamp(),
        file_path: format!("{} files/processes", alerts.len()),
        process_name: "Multiple Processes".to_string(),
        pid: 0,
        threat_type: "GroupedBurst".to_string(),
        threat_name: format!("{} threats grouped", alerts.len()),
        severity: top.severity,
        detection_engines: vec!["CyberShield Correlator".to_string()],
        confidence: 0.95,
        ai_explanation: format!(
            "CyberShield grouped {} detections in a 2-minute burst to reduce spam. Top matches: {}.",
            alerts.len(),
            names
        ),
    }
}

fn severity_rank(sev: &AlertSeverity) -> u8 {
    match sev {
        AlertSeverity::Critical => 4,
        AlertSeverity::High => 3,
        AlertSeverity::Medium => 2,
        AlertSeverity::Low => 1,
    }
}

async fn live_process_scanner(
    tx: mpsc::Sender<ScanJob>,
    settings: Arc<tokio::sync::RwLock<api::ServiceSettings>>,
) {
    tracing::info!("Live process scanner active");
    let mut scanned_pids: HashSet<i32> = HashSet::new();

    loop {
        if !settings.read().await.real_time_protection {
            sleep(Duration::from_secs(2)).await;
            continue;
        }

        let proc_execs = collect_process_exec_targets();
        let mut seen_now = HashSet::new();
        for (pid, exe_path) in proc_execs {
            seen_now.insert(pid);
            if scanned_pids.contains(&pid) {
                continue;
            }
            if is_system_process_path(Path::new(&exe_path)) {
                scanned_pids.insert(pid);
                continue;
            }
            let _ = tx
                .send(ScanJob {
                    path: exe_path,
                    source: ScanSource::Realtime,
                })
                .await;
            record_process_event();
            scanned_pids.insert(pid);
        }
        scanned_pids.retain(|pid| seen_now.contains(pid));
        sleep(LIVE_PROCESS_SCAN_INTERVAL).await;
    }
}

#[cfg(target_os = "linux")]
fn collect_process_exec_targets() -> Vec<(i32, String)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let pid_str = file_name.to_string_lossy();
        let Ok(pid) = pid_str.parse::<i32>() else {
            continue;
        };
        let exe_link = format!("/proc/{pid}/exe");
        if let Ok(path) = std::fs::read_link(exe_link) {
            let exe = path.to_string_lossy().to_string();
            if !exe.is_empty() && Path::new(&exe).exists() {
                out.push((pid, exe));
            }
        }
    }
    out
}

#[cfg(not(target_os = "linux"))]
fn collect_process_exec_targets() -> Vec<(i32, String)> {
    Vec::new()
}

fn is_system_process_path(path: &Path) -> bool {
    let p = path.to_string_lossy().to_ascii_lowercase();
    p.starts_with("/usr/")
        || p.starts_with("/lib/")
        || p.starts_with("/sbin/")
        || p.starts_with("/bin/")
        || p.starts_with("/snap/")
        || p.contains("\\windows\\")
}

async fn live_network_scanner(
    threats: Arc<tokio::sync::Mutex<Vec<ThreatEntry>>>,
    events: broadcast::Sender<RealtimeEvent>,
    alert_tx: mpsc::Sender<ThreatAlert>,
    settings: Arc<tokio::sync::RwLock<api::ServiceSettings>>,
) {
    tracing::info!("Live network scanner active");
    let mut seen: HashSet<String> = HashSet::new();

    loop {
        if !settings.read().await.real_time_protection {
            sleep(Duration::from_secs(2)).await;
            continue;
        }

        for conn in api::collect_network_logs() {
            if !conn.suspicious {
                continue;
            }

            let key = format!(
                "{}|{}|{}|{}",
                conn.protocol, conn.local_address, conn.remote_address, conn.state
            );
            if seen.contains(&key) {
                continue;
            }
            seen.insert(key);

            let process = conn
                .process
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            let detail = format!(
                "Suspicious {} connection from {} to {} ({})",
                conn.protocol, conn.local_address, conn.remote_address, conn.state
            );
            let entry = ThreatEntry {
                id: Uuid::new_v4().to_string(),
                name: "Suspicious.Network.Activity".to_string(),
                path: format!("network://{}", conn.remote_address),
                severity: "High".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                engine: "Network Behavioral".to_string(),
                action: "PendingUserDecision".to_string(),
                details: Some(detail.clone()),
            };

            {
                let mut t = threats.lock().await;
                t.insert(0, entry.clone());
                if t.len() > THREAT_HISTORY_LIMIT {
                    t.truncate(THREAT_HISTORY_LIMIT);
                }
            }
            let _ = events.send(RealtimeEvent::ThreatDetected(entry));
            record_network_event();
            record_threat();

            let alert = ThreatAlert {
                id: Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp(),
                file_path: format!("network://{}", conn.remote_address),
                process_name: process,
                pid: 0,
                threat_type: "Network".to_string(),
                threat_name: "Suspicious outbound connection".to_string(),
                severity: AlertSeverity::High,
                detection_engines: vec!["Network Behavioral".to_string()],
                confidence: 0.82,
                ai_explanation: format!(
                    "This device opened a suspicious connection to {} using {}. If unexpected, block or monitor immediately.",
                    conn.remote_address, conn.protocol
                ),
            };
            let _ = alert_tx.send(alert).await;
        }

        sleep(LIVE_NETWORK_SCAN_INTERVAL).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_kernel_event(
    event: ParsedEvent,
    scan_tx: mpsc::Sender<ScanJob>,
    settings: Arc<tokio::sync::RwLock<api::ServiceSettings>>,
    network_detector: Arc<NetworkThreatDetector>,
    threats: Arc<tokio::sync::Mutex<Vec<ThreatEntry>>>,
    events: broadcast::Sender<RealtimeEvent>,
    alert_tx: mpsc::Sender<ThreatAlert>,
    quarantine_dir: Arc<String>,
    net_seen: Arc<Mutex<HashSet<String>>>,
) {
    if !settings.read().await.real_time_protection {
        return;
    }

    let normalized = normalize_kernel_event(event);
    let policy_outcome = evaluate_kernel_policy(&normalized);
    let audit = KernelPolicyAuditRecord {
        event: normalized.clone(),
        outcome: policy_outcome.clone(),
    };
    if let Err(e) = append_policy_audit(&audit) {
        tracing::warn!("failed to append policy audit record: {}", e);
    } else {
        tracing::info!(
            "policy audit appended: pid={} decision={:?} kind={:?}",
            normalized.pid,
            policy_outcome.decision,
            normalized.kind
        );
    }

    match normalized.kind {
        KernelEventKind::FileAccess | KernelEventKind::ProcessExec => {
            if matches!(policy_outcome.decision, PolicyDecision::Allow) {
                return;
            }
            stats::record_event();
            record_drive_event();
            let path = normalized.path.clone().unwrap_or_default();
            if !path.is_empty() {
                #[cfg(target_os = "linux")]
                if matches!(
                    policy_outcome.decision,
                    PolicyDecision::Block | PolicyDecision::Quarantine
                ) {
                    let quarantine = matches!(policy_outcome.decision, PolicyDecision::Quarantine);
                    if let Err(e) = set_pid_enforcement_action(normalized.pid, quarantine) {
                        tracing::warn!(
                            "failed to program inline kernel enforcement for pid {}: {}",
                            normalized.pid,
                            e
                        );
                    } else {
                        tracing::info!(
                            "programmed inline kernel enforcement for pid {} decision {:?}",
                            normalized.pid,
                            policy_outcome.decision
                        );
                    }
                }

                if matches!(policy_outcome.decision, PolicyDecision::Quarantine) {
                    if let Ok(qmsg) = quarantine_for_kernel_event(&path, quarantine_dir.as_ref()) {
                        tracing::warn!("kernel policy quarantine action: {}", qmsg);
                    }
                }

                if matches!(
                    policy_outcome.decision,
                    PolicyDecision::Block | PolicyDecision::Quarantine
                ) {
                    let entry = ThreatEntry {
                        id: Uuid::new_v4().to_string(),
                        name: format!(
                            "Kernel.Policy.{}",
                            match policy_outcome.decision {
                                PolicyDecision::Allow => "allow",
                                PolicyDecision::Monitor => "monitor",
                                PolicyDecision::Quarantine => "quarantine",
                                PolicyDecision::Block => "block",
                            }
                        ),
                        path: path.clone(),
                        severity: policy_outcome.severity.clone(),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        engine: "Kernel Policy Engine".to_string(),
                        action: format!("{:?}", policy_outcome.decision),
                        details: Some(policy_outcome.reason.clone()),
                    };

                    {
                        let mut t = threats.lock().await;
                        t.insert(0, entry.clone());
                        if t.len() > THREAT_HISTORY_LIMIT {
                            t.truncate(THREAT_HISTORY_LIMIT);
                        }
                    }
                    let _ = events.send(RealtimeEvent::ThreatDetected(entry));
                    record_threat();

                    let alert = ThreatAlert {
                        id: Uuid::new_v4().to_string(),
                        timestamp: chrono::Utc::now().timestamp(),
                        file_path: path.clone(),
                        process_name: normalized.comm.clone(),
                        pid: normalized.pid as i32,
                        threat_type: "KernelPolicy".to_string(),
                        threat_name: "Kernel policy intervention".to_string(),
                        severity: if policy_outcome.severity.eq_ignore_ascii_case("critical") {
                            AlertSeverity::Critical
                        } else if policy_outcome.severity.eq_ignore_ascii_case("high") {
                            AlertSeverity::High
                        } else if policy_outcome.severity.eq_ignore_ascii_case("medium") {
                            AlertSeverity::Medium
                        } else {
                            AlertSeverity::Low
                        },
                        detection_engines: vec!["Kernel Policy Engine".to_string()],
                        confidence: policy_outcome.confidence,
                        ai_explanation: policy_outcome.reason.clone(),
                    };
                    let _ = alert_tx.send(alert).await;
                }

                let _ = scan_tx
                    .send(ScanJob {
                        path,
                        source: ScanSource::Realtime,
                    })
                    .await;
            }
        }
        KernelEventKind::NetworkConnect => {
            if matches!(policy_outcome.decision, PolicyDecision::Allow) {
                return;
            }
            let pid = normalized.pid;
            let ip = normalized.network_ip.unwrap_or_default();
            let port = normalized.network_port.unwrap_or_default();
            let comm = normalized.comm;
            record_network_event();
            let key = format!("{ip}:{port}:{comm}");
            {
                let mut seen = net_seen.lock().await;
                if seen.contains(&key) {
                    return;
                }
                seen.insert(key);
                if seen.len() > 10_000 {
                    seen.clear();
                }
            }

            let verdict = network_detector.analyze_connection(&comm, &ip, port);
            if matches!(verdict, ConnectionVerdict::Clean) {
                if !matches!(policy_outcome.decision, PolicyDecision::Block) {
                    return;
                }
            }

            let (threat_name, severity, confidence) = match &verdict {
                ConnectionVerdict::Malicious {
                    threat_name,
                    severity,
                    ..
                } => (threat_name.clone(), severity.clone(), 0.95),
                ConnectionVerdict::Suspicious {
                    threat_name,
                    severity,
                    ..
                } => (threat_name.clone(), severity.clone(), 0.80),
                ConnectionVerdict::Clean => return,
            };

            let detail = network_detector.ai_explanation(&verdict, &comm);
            let entry = ThreatEntry {
                id: Uuid::new_v4().to_string(),
                name: threat_name.clone(),
                path: format!("network://{}:{}", ip, port),
                severity: severity.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                engine: "Network Threat Detector".to_string(),
                action: "PendingUserDecision".to_string(),
                details: Some(detail.clone()),
            };

            {
                let mut t = threats.lock().await;
                t.insert(0, entry.clone());
                if t.len() > THREAT_HISTORY_LIMIT {
                    t.truncate(THREAT_HISTORY_LIMIT);
                }
            }
            let _ = events.send(RealtimeEvent::ThreatDetected(entry));
            record_threat();

            let alert = ThreatAlert {
                id: Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp(),
                file_path: format!("network://{}:{}", ip, port),
                process_name: comm,
                pid: pid as i32,
                threat_type: "Network".to_string(),
                threat_name,
                severity: if severity.eq_ignore_ascii_case("critical") {
                    AlertSeverity::Critical
                } else if severity.eq_ignore_ascii_case("high") {
                    AlertSeverity::High
                } else if severity.eq_ignore_ascii_case("medium") {
                    AlertSeverity::Medium
                } else {
                    AlertSeverity::Low
                },
                detection_engines: vec!["Network Threat Detector".to_string()],
                confidence,
                ai_explanation: detail,
            };
            let _ = alert_tx.send(alert).await;
        }
    }
}

fn quarantine_for_kernel_event(path: &str, quarantine_dir: &str) -> anyhow::Result<String> {
    let source = Path::new(path);
    if !source.exists() || !source.is_file() {
        anyhow::bail!("cannot quarantine non-file path: {}", path);
    }

    std::fs::create_dir_all(quarantine_dir)?;
    let file_name = source
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let destination = Path::new(quarantine_dir).join(format!(
        "{}_{}_{}",
        chrono::Utc::now().timestamp(),
        Uuid::new_v4(),
        file_name
    ));

    std::fs::rename(source, &destination)?;
    Ok(format!("quarantined to {}", destination.display()))
}

fn load_watch_paths() -> Vec<String> {
    if let Ok(raw) = std::env::var("AV_WATCH_PATHS") {
        let from_env = raw
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if !from_env.is_empty() {
            return from_env;
        }
    }

    let mut defaults = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        defaults.push(format!("{}/Downloads", home));
        defaults.push(format!("{}/Desktop", home));
    }
    defaults
}

fn collect_watch_snapshot(
    paths: &[String],
    max_files: usize,
    max_depth: usize,
) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    let mut queue: VecDeque<(std::path::PathBuf, usize)> = VecDeque::new();

    for p in paths {
        queue.push_back((std::path::PathBuf::from(p), 0));
    }

    while let Some((path, depth)) = queue.pop_front() {
        if out.len() >= max_files {
            break;
        }

        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };

        if metadata.is_file() {
            if !is_realtime_priority_path(&path) {
                continue;
            }
            let modified = metadata
                .modified()
                .ok()
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            out.push((path.to_string_lossy().to_string(), modified));
            continue;
        }

        if !metadata.is_dir() || depth >= max_depth {
            continue;
        }
        if should_skip_watch_dir(&path) {
            continue;
        }

        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };

        for entry in entries.flatten() {
            queue.push_back((entry.path(), depth + 1));
            if queue.len() > max_files.saturating_mul(4) {
                break;
            }
        }
    }

    out
}

fn should_skip_watch_dir(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    matches!(
        name.as_str(),
        ".git" | "node_modules" | "target" | "__pycache__" | ".cache" | ".cargo" | "cache" | "tmp"
    )
}

fn is_realtime_priority_path(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    if ext.is_empty() {
        return false;
    }

    if matches!(
        ext.as_str(),
        "exe"
            | "dll"
            | "sys"
            | "bin"
            | "so"
            | "dylib"
            | "app"
            | "jar"
            | "apk"
            | "msi"
            | "deb"
            | "rpm"
            | "zip"
            | "rar"
            | "7z"
            | "tar"
            | "gz"
            | "ps1"
            | "bat"
            | "cmd"
            | "js"
            | "vbs"
            | "sh"
            | "py"
            | "rb"
            | "doc"
            | "docx"
            | "xls"
            | "xlsx"
            | "ppt"
            | "pptx"
            | "pdf"
            | "html"
            | "hta"
    ) {
        return true;
    }

    path.to_string_lossy()
        .to_ascii_lowercase()
        .contains("/downloads/")
}

fn friendly_explanation_for_detection(path: &str, detection: &engines::DetectionResult) -> String {
    let file_label = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path);
    let confidence = (detection.confidence * 100.0).round();

    match detection.level {
        engines::ThreatLevel::Malicious => format!(
            "This looks like a harmful file named '{file_label}'. It may steal data or damage your system. Detection confidence is about {confidence:.0}%. We recommend blocking it."
        ),
        engines::ThreatLevel::Suspicious => format!(
            "This file '{file_label}' is acting in a risky way. It may still be harmless, but there are warning signs. Detection confidence is about {confidence:.0}%. Monitoring is safer unless you trust it."
        ),
        engines::ThreatLevel::Clean => "No threat found.".to_string(),
    }
}

fn hash_file_streaming(path: &Path) -> anyhow::Result<String> {
    const LARGE_FILE_THRESHOLD: u64 = 100 * 1024 * 1024;
    const HASH_PREFIX_LIMIT: u64 = 10 * 1024 * 1024;

    let metadata = std::fs::metadata(path)?;
    let max_bytes = if metadata.len() > LARGE_FILE_THRESHOLD {
        tracing::warn!(
            "Large file detected ({} MB), hashing first 10 MB only: {}",
            metadata.len() / 1024 / 1024,
            path.display()
        );
        HASH_PREFIX_LIMIT
    } else {
        metadata.len()
    };

    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(8 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut bytes_read: u64 = 0;

    loop {
        if bytes_read >= max_bytes {
            break;
        }
        let read_len = (max_bytes - bytes_read).min(buffer.len() as u64) as usize;
        let n = reader.read(&mut buffer[..read_len])?;
        if n == 0 {
            break;
        }
        let n = n.min(read_len);
        hasher.update(&buffer[..n]);
        bytes_read += n as u64;
    }

    Ok(hex::encode(hasher.finalize()))
}

async fn monitor_self_resources(scan_throttle_ms: Arc<RwLock<u64>>) {
    let mut prev_proc = read_self_cpu_jiffies().unwrap_or(0);
    let mut prev_total = read_total_cpu_jiffies().unwrap_or(0);

    loop {
        sleep(Duration::from_secs(2)).await;

        let memory_mb = read_self_memory_mb().unwrap_or(0);
        let proc_now = read_self_cpu_jiffies().unwrap_or(prev_proc);
        let total_now = read_total_cpu_jiffies().unwrap_or(prev_total);

        let proc_delta = proc_now.saturating_sub(prev_proc) as f64;
        let total_delta = total_now.saturating_sub(prev_total) as f64;
        prev_proc = proc_now;
        prev_total = total_now;

        let cpu_usage = if total_delta > 0.0 {
            (proc_delta / total_delta * 100.0) as f32
        } else {
            0.0
        };
        set_resource_usage(cpu_usage as f64, memory_mb);

        let next_delay = if cpu_usage > 50.0 || memory_mb > 400 {
            2000
        } else if cpu_usage > 30.0 || memory_mb > 300 {
            500
        } else if cpu_usage > 15.0 || memory_mb > 200 {
            120
        } else {
            10
        };

        {
            let mut guard = scan_throttle_ms.write().await;
            *guard = next_delay;
        }

        if next_delay > 100 {
            tracing::warn!(
                "high resource usage detected (cpu={:.1}%, memory={}MB), throttling scans to {}ms delay",
                cpu_usage,
                memory_mb,
                next_delay
            );
        }
    }
}

fn read_self_memory_mb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb = rest
                .split_whitespace()
                .next()
                .and_then(|x| x.parse::<u64>().ok())?;
            return Some(kb / 1024);
        }
    }
    None
}

fn read_self_cpu_jiffies() -> Option<u64> {
    // /proc/self/stat fields:
    // 14: utime, 15: stime (both in ticks/jiffies)
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let parts: Vec<&str> = stat.split_whitespace().collect();
    let utime = parts.get(13)?.parse::<u64>().ok()?;
    let stime = parts.get(14)?.parse::<u64>().ok()?;
    Some(utime + stime)
}

fn read_total_cpu_jiffies() -> Option<u64> {
    // /proc/stat first line "cpu  ..."
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let first = stat.lines().next()?;
    let mut parts = first.split_whitespace();
    if parts.next()? != "cpu" {
        return None;
    }
    let mut total = 0u64;
    for value in parts {
        total = total.saturating_add(value.parse::<u64>().ok()?);
    }
    Some(total)
}
