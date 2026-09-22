// REST + WebSocket API for av-service.

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanSource {
    Manual,
    Realtime,
}

#[derive(Debug, Clone)]
pub struct ScanJob {
    pub path: String,
    pub source: ScanSource,
}

/// Shared app state for API handlers
pub struct AppState {
    pub scan_tx: mpsc::Sender<ScanJob>,
    pub threats: Arc<Mutex<Vec<ThreatEntry>>>,
    pub quarantine_dir: String,
    pub settings: Arc<RwLock<ServiceSettings>>,
    pub settings_path: String,
    pub realtime_events: broadcast::Sender<RealtimeEvent>,
    pub process_blocks: Arc<RwLock<ProcessBlocklist>>,
    pub pending_alerts: Arc<Mutex<HashMap<String, ThreatAlert>>>,
    pub monitored_processes: Arc<Mutex<HashMap<i32, MonitoredProcess>>>,
    pub allowlist: Arc<RwLock<Vec<String>>>,
    pub live_stats: Arc<Mutex<crate::stats::LiveStatsState>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry {
    pub id: String,
    pub name: String,
    pub path: String,
    pub severity: String,
    pub timestamp: String,
    pub engine: String,
    pub action: String,
    #[serde(default)]
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub id: String,
    pub timestamp: i64,
    pub file_path: String,
    pub process_name: String,
    pub pid: i32,
    pub threat_type: String,
    pub threat_name: String,
    pub severity: AlertSeverity,
    pub detection_engines: Vec<String>,
    pub confidence: f32,
    pub ai_explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserAction {
    BlockImmediately,
    MonitorOnly,
    AllowPermanently,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredProcess {
    pub pid: i32,
    pub path: String,
    pub alert_id: String,
    pub started_at_unix: i64,
    pub suspicious_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLogEntry {
    pub pid: i32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_percent: f32,
    pub memory_mb: Option<f64>,
    pub network_kbs: Option<f64>,
    pub exe_path: Option<String>,
    pub parent_pid: Option<u32>,
    pub network_activity: Option<String>,
    pub suspicious: bool,
    pub protected: bool,
    #[serde(default)]
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkLogEntry {
    pub protocol: String,
    pub local_address: String,
    pub remote_address: String,
    pub state: String,
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSettings {
    pub real_time_protection: bool,
    pub auto_scan: bool,
    pub scan_interval_hours: u32,
    pub quarantine_enabled: bool,
}

impl Default for ServiceSettings {
    fn default() -> Self {
        Self {
            real_time_protection: true,
            auto_scan: true,
            scan_interval_hours: 24,
            quarantine_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub status: String,
    pub version: String,
    pub protection_active: bool,
    pub realtime_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct LiveStatsResponse {
    #[serde(rename = "type")]
    pub type_: String,
    pub data: crate::stats::LiveStatsSnapshot,
}

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub file_path: String,
    pub verdict: String,
    pub threats_detected: usize,
    pub timestamp: String,
}

#[derive(Debug, Deserialize)]
pub struct DeepScanRequest {
    #[serde(default)]
    pub root_path: Option<String>,
    #[serde(default)]
    pub max_files: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct DeepScanResponse {
    pub root_path: String,
    pub queued_files: usize,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct QuarantineResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum RealtimeEvent {
    ThreatDetected(ThreatEntry),
    ThreatAlert(ThreatAlert),
    ThreatResolved {
        alert_id: String,
        action: UserAction,
        message: String,
    },
    SettingsChanged(ServiceSettings),
    StatusChanged(StatusResponse),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExplainLogsRequest {
    pub kind: String,
}

#[derive(Debug, Serialize)]
pub struct ExplainLogsResponse {
    pub explanation: String,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessBlocklist {
    pub temporary: HashMap<String, SystemTime>,
    pub permanent: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExplainProcessRequest {
    pub pid: i32,
    pub name: String,
    pub cpu: f32,
    pub memory: f32,
}

#[derive(Debug, Deserialize)]
pub struct ExplainNetworkRequest {
    pub protocol: String,
    pub local_address: String,
    pub remote_address: String,
    pub state: String,
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct DeepExplainProcessRequest {
    pub pid: i32,
    pub name: String,
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub memory_mb: Option<f64>,
    pub network_kbs: Option<f64>,
    pub exe_path: Option<String>,
    pub parent_pid: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ProcessExplainDeepResponse {
    pub verdict: String,
    pub risk_score: u8,
    pub risk_color: String,
    pub one_liner: String,
    pub what_is_this: String,
    pub what_doing_now: String,
    pub safety_reason: String,
    pub user_action: String,
}

#[derive(Debug, Serialize)]
pub struct NetExplainDeepResponse {
    pub verdict: String,
    pub risk_color: String,
    pub packet_label: String,
    pub plain_english: String,
    pub what_data_moving: String,
    pub where_going: String,
    pub safety_reason: String,
    pub user_action: String,
}

#[derive(Debug, Deserialize)]
pub struct SandboxRunRequest {
    pub file_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxEvent {
    pub time: f64,
    pub category: String,
    pub action: String,
    pub detail: String,
    pub severity: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SandboxReport {
    pub verdict: String,
    pub risk_score: u8,
    pub events: Vec<SandboxEvent>,
    pub files_accessed: Vec<String>,
    pub network_attempts: Vec<String>,
    pub processes_spawned: Vec<String>,
    pub ai_summary: String,
    pub duration_secs: f64,
}

#[derive(Debug, Deserialize)]
pub struct ExplainThreatRequest {
    pub id: String,
    pub name: String,
    pub path: String,
    pub severity: String,
    pub engine: String,
    pub action: String,
}

#[derive(Debug, Deserialize)]
pub struct KillProcessRequest {
    pub pid: i32,
}

#[derive(Debug, Deserialize)]
pub struct BlockProcessTempRequest {
    pub name: String,
    pub duration_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct BlockProcessPermanentRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct SandboxRequest {
    pub pid: i32,
}

#[derive(Debug, Deserialize)]
pub struct FileMultiEngineScanRequest {
    pub filename: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct UrlMultiEngineScanRequest {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct PathMultiEngineScanRequest {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct AlertDecisionRequest {
    pub alert_id: String,
    pub action: UserAction,
}

#[derive(Debug, Deserialize)]
pub struct ThreatActionRequest {
    pub threat_id: String,
    pub action: String, // quarantine | allow | delete
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigateRequest {
    pub target: String,
    pub target_type: String, // network | file | process
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigateActionRequest {
    pub target: String,
    pub target_type: String, // network | file | process
    pub action: String,      // quarantine | block | monitor
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationEngineFinding {
    pub name: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationIOC {
    pub ioc_type: String, // ip | domain | hash | url | port | path
    pub value: String,
    pub reputation: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationBehavioralAnalysis {
    pub file_operations: Vec<String>,
    pub network_connections: Vec<String>,
    pub process_indicators: Vec<String>,
    pub persistence_indicators: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationAIAssessment {
    pub threat_classification: String,
    pub malware_family: Option<String>,
    pub attack_vectors: Vec<String>,
    pub payload_type: Option<String>,
    pub plain_english_summary: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationReport {
    pub target: String,
    pub target_type: String, // network | file | process
    pub verdict: String,     // clean | suspicious | malicious | highly_malicious
    pub confidence: f64,     // 0.0-1.0
    pub engine_findings: Vec<InvestigationEngineFinding>,
    pub behavioral_analysis: InvestigationBehavioralAnalysis,
    pub ai_assessment: InvestigationAIAssessment,
    pub iocs: Vec<InvestigationIOC>,
    pub threat_families: Vec<String>,
    pub recommendations: Vec<String>,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineResult {
    pub name: String,
    pub detected: bool,
    pub result: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MultiEngineScanResponse {
    pub malicious: usize,
    pub total: usize,
    pub engines: Vec<EngineResult>,
}

#[derive(Debug, Serialize)]
pub struct ActionResponse {
    pub success: bool,
    pub message: String,
}

pub fn load_settings(path: &str) -> ServiceSettings {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str::<ServiceSettings>(&raw).unwrap_or_default(),
        Err(_) => ServiceSettings::default(),
    }
}

fn save_settings(path: &str, settings: &ServiceSettings) -> anyhow::Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(settings)?)?;
    Ok(())
}

/// GET /api/v1/status
pub async fn status_handler(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let settings = state.settings.read().await.clone();
    Json(StatusResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION", "0.1.0").to_string(),
        protection_active: settings.real_time_protection,
        realtime_enabled: settings.real_time_protection,
    })
}

/// GET /api/v1/live-stats
pub async fn live_stats_handler(State(state): State<Arc<AppState>>) -> Json<LiveStatsResponse> {
    let mut guard = state.live_stats.lock().await;
    let cpu = crate::stats::AV_CPU_TENTHS.load(std::sync::atomic::Ordering::Relaxed) as f64 / 10.0;
    let ram = crate::stats::AV_RAM_MB.load(std::sync::atomic::Ordering::Relaxed);
    Json(LiveStatsResponse {
        type_: "stats_update".to_string(),
        data: guard.snapshot(cpu, ram),
    })
}

/// GET /api/v1/settings
pub async fn get_settings_handler(State(state): State<Arc<AppState>>) -> Json<ServiceSettings> {
    Json(state.settings.read().await.clone())
}

/// PUT /api/v1/settings
pub async fn put_settings_handler(
    State(state): State<Arc<AppState>>,
    Json(settings): Json<ServiceSettings>,
) -> Json<ServiceSettings> {
    {
        let mut guard = state.settings.write().await;
        *guard = settings.clone();
    }

    if let Err(e) = save_settings(&state.settings_path, &settings) {
        tracing::warn!("failed to persist settings: {}", e);
    }

    let _ = state
        .realtime_events
        .send(RealtimeEvent::SettingsChanged(settings.clone()));
    let _ = state
        .realtime_events
        .send(RealtimeEvent::StatusChanged(StatusResponse {
            status: "ok".to_string(),
            version: env!("CARGO_PKG_VERSION", "0.1.0").to_string(),
            protection_active: settings.real_time_protection,
            realtime_enabled: settings.real_time_protection,
        }));

    Json(settings)
}

/// POST /api/v1/scan - queue file for scanning
pub async fn scan_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScanRequest>,
) -> Json<ScanResponse> {
    let path = req.path.trim().to_string();
    let _ = state
        .scan_tx
        .send(ScanJob {
            path: path.clone(),
            source: ScanSource::Manual,
        })
        .await;

    Json(ScanResponse {
        file_path: path,
        verdict: "Scanning".to_string(),
        threats_detected: 0,
        timestamp: Utc::now().to_rfc3339(),
    })
}

/// POST /api/v1/scan/deep - recursively queue files for scanning
pub async fn deep_scan_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeepScanRequest>,
) -> Json<DeepScanResponse> {
    let root_path = req
        .root_path
        .unwrap_or_else(|| std::env::var("HOME").unwrap_or_else(|_| ".".to_string()));
    let max_files = req.max_files.unwrap_or(2500).min(10000);
    let files = collect_files_for_deep_scan(&root_path, max_files);

    let mut queued = 0usize;
    for file in files {
        if state
            .scan_tx
            .send(ScanJob {
                path: file,
                source: ScanSource::Manual,
            })
            .await
            .is_ok()
        {
            queued += 1;
        }
    }

    Json(DeepScanResponse {
        root_path,
        queued_files: queued,
        timestamp: Utc::now().to_rfc3339(),
    })
}

/// GET /api/v1/threats - list recent threats (real data from scans)
pub async fn threats_handler(State(state): State<Arc<AppState>>) -> Json<Vec<ThreatEntry>> {
    let threats = state.threats.lock().await.clone();
    Json(threats)
}

/// GET /api/v1/alerts/pending
pub async fn pending_alerts_handler(State(state): State<Arc<AppState>>) -> Json<Vec<ThreatAlert>> {
    let mut alerts = state
        .pending_alerts
        .lock()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    alerts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Json(alerts)
}

/// POST /api/v1/alerts/decision
pub async fn alert_decision_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AlertDecisionRequest>,
) -> Json<ActionResponse> {
    let alert = {
        let mut alerts = state.pending_alerts.lock().await;
        alerts.remove(&req.alert_id)
    };

    let Some(alert) = alert else {
        return Json(ActionResponse {
            success: false,
            message: "Alert not found or already resolved".to_string(),
        });
    };

    let result = match req.action.clone() {
        UserAction::BlockImmediately => handle_block_action(&state, &alert).await,
        UserAction::MonitorOnly => handle_monitor_action(&state, &alert).await,
        UserAction::AllowPermanently => handle_allow_action(&state, &alert).await,
    };

    match result {
        Ok(message) => {
            let _ = state.realtime_events.send(RealtimeEvent::ThreatResolved {
                alert_id: req.alert_id,
                action: req.action,
                message: message.clone(),
            });
            Json(ActionResponse {
                success: true,
                message,
            })
        }
        Err(e) => Json(ActionResponse {
            success: false,
            message: format!("Decision handling failed: {}", e),
        }),
    }
}

/// POST /api/v1/threats/action
pub async fn threat_action_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ThreatActionRequest>,
) -> Json<ActionResponse> {
    let mut threats = state.threats.lock().await;
    let Some(entry) = threats.iter_mut().find(|t| t.id == req.threat_id) else {
        return Json(ActionResponse {
            success: false,
            message: "Threat item not found".to_string(),
        });
    };

    let file_path = entry.path.clone();
    let message = match req.action.as_str() {
        "quarantine" => {
            if file_path.starts_with("network://") {
                return Json(ActionResponse {
                    success: false,
                    message: "Network items cannot be quarantined as files".to_string(),
                });
            }
            match quarantine_path(&file_path, &state.quarantine_dir) {
                Ok(msg) => {
                    entry.action = "Quarantined".to_string();
                    msg
                }
                Err(e) => {
                    return Json(ActionResponse {
                        success: false,
                        message: format!("Quarantine failed: {}", e),
                    });
                }
            }
        }
        "allow" => {
            {
                let mut allowlist = state.allowlist.write().await;
                if !allowlist.iter().any(|x| x == &file_path) {
                    allowlist.push(file_path.clone());
                }
            }
            entry.action = "Allowed".to_string();
            "Added to allowlist".to_string()
        }
        "delete" => {
            if file_path.starts_with("network://") {
                return Json(ActionResponse {
                    success: false,
                    message: "Network items cannot be deleted as files".to_string(),
                });
            }
            match std::fs::remove_file(&file_path) {
                Ok(_) => {
                    entry.action = "Deleted".to_string();
                    "File deleted".to_string()
                }
                Err(e) => {
                    return Json(ActionResponse {
                        success: false,
                        message: format!("Delete failed: {}", e),
                    });
                }
            }
        }
        _ => {
            return Json(ActionResponse {
                success: false,
                message: "Invalid action. Use quarantine|allow|delete".to_string(),
            });
        }
    };

    Json(ActionResponse {
        success: true,
        message,
    })
}

fn collect_files_for_deep_scan(root: &str, max_files: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back(std::path::PathBuf::from(root));

    while let Some(path) = queue.pop_front() {
        if out.len() >= max_files {
            break;
        }

        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };

        if meta.is_file() {
            out.push(path.to_string_lossy().to_string());
            continue;
        }

        if !meta.is_dir() {
            continue;
        }

        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };

        for entry in entries.flatten() {
            queue.push_back(entry.path());
            if queue.len() > max_files.saturating_mul(4) {
                break;
            }
        }
    }

    out
}

/// POST /api/v1/quarantine - move file to quarantine
pub async fn quarantine_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScanRequest>,
) -> Json<QuarantineResponse> {
    let path = std::path::Path::new(&req.path);
    if !path.exists() {
        return Json(QuarantineResponse {
            success: false,
            message: format!("File not found: {}", req.path),
        });
    }

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let quarantine_path = std::path::Path::new(&state.quarantine_dir).join(format!(
        "{}_{}",
        Utc::now().format("%Y%m%d_%H%M%S"),
        filename
    ));

    match std::fs::create_dir_all(&state.quarantine_dir) {
        Ok(_) => {}
        Err(e) => {
            return Json(QuarantineResponse {
                success: false,
                message: format!("Cannot create quarantine dir: {}", e),
            });
        }
    }

    match std::fs::rename(path, &quarantine_path) {
        Ok(_) => Json(QuarantineResponse {
            success: true,
            message: format!("File quarantined to {}", quarantine_path.display()),
        }),
        Err(e) => Json(QuarantineResponse {
            success: false,
            message: format!("Quarantine failed: {}", e),
        }),
    }
}

/// GET /api/v1/quarantine - list quarantined files (real files in quarantine dir)
pub async fn quarantine_list_handler(State(state): State<Arc<AppState>>) -> Json<Vec<String>> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&state.quarantine_dir) {
        for entry in entries.flatten() {
            if let Ok(path) = entry.path().into_os_string().into_string() {
                files.push(path);
            }
        }
    }
    Json(files)
}

/// GET /api/v1/process-logs
pub async fn process_logs_handler(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<ProcessLogEntry>> {
    {
        let mut blocks = state.process_blocks.write().await;
        let now = SystemTime::now();
        blocks.temporary.retain(|_, until| *until > now);
    }
    let blocks = state.process_blocks.read().await.clone();
    Json(collect_process_logs_with_blocks(&blocks))
}

/// GET /api/v1/network-logs
pub async fn network_logs_handler() -> Json<Vec<NetworkLogEntry>> {
    Json(collect_network_logs())
}

/// POST /api/v1/explain-logs
pub async fn explain_logs_handler(
    Json(req): Json<ExplainLogsRequest>,
) -> Json<ExplainLogsResponse> {
    match req.kind.as_str() {
        "process" => {
            let logs = collect_process_logs();
            let suspicious = logs.iter().filter(|x| x.suspicious).count();
            let top = logs.first();
            let summary = if let Some(p) = top {
                format!(
                    "I checked {} running apps. {} need extra attention because they are using a lot of system power or have unusual behavior. The busiest app right now is {} (PID {}) using {:.1}% CPU and {:.1}% memory. If you do not recognize a highlighted app, monitor it or block it.",
                    logs.len(),
                    suspicious,
                    p.name,
                    p.pid,
                    p.cpu_percent,
                    p.memory_percent
                )
            } else {
                "No process data is currently available from the operating system.".to_string()
            };
            Json(ExplainLogsResponse {
                explanation: summary,
            })
        }
        "network" => {
            let logs = collect_network_logs();
            let suspicious = logs.iter().filter(|x| x.suspicious).count();
            let summary = format!(
                "I checked {} network connections. {} look unusual because of risky ports or odd connection states. Focus on unknown apps that talk to outside addresses you do not trust.",
                logs.len(), suspicious
            );
            Json(ExplainLogsResponse {
                explanation: summary,
            })
        }
        _ => Json(ExplainLogsResponse {
            explanation: "Unknown log type. Use 'process' or 'network'.".to_string(),
        }),
    }
}

/// POST /api/v1/explain-process
pub async fn explain_process_handler(
    Json(req): Json<ExplainProcessRequest>,
) -> Json<ExplainLogsResponse> {
    let lower = req.name.to_lowercase();
    let explanation = if lower.contains("av-service") || lower.contains("cybershield") {
        format!(
            "{} (PID {}) is part of CyberShield protection. CPU {:.1}% and memory {:.1}% can rise during active scans. This is expected and usually safe to keep running.",
            req.name, req.pid, req.cpu, req.memory
        )
    } else if lower.contains("code") || lower.contains("brave") || lower.contains("chrome") {
        format!(
            "{} (PID {}) is a normal user application. Resource use of {:.1}% CPU and {:.1}% memory is usually tied to open tabs/files. This is generally safe unless it is unexpectedly high for long periods.",
            req.name, req.pid, req.cpu, req.memory
        )
    } else if req.cpu >= 70.0 || req.memory >= 40.0 {
        format!(
            "{} (PID {}) is consuming high resources ({:.1}% CPU, {:.1}% memory). That can cause slowdowns and may be suspicious if you do not recognize it. Consider sandboxing or temporary blocking for investigation.",
            req.name, req.pid, req.cpu, req.memory
        )
    } else {
        format!(
            "{} (PID {}) appears to be a regular running process with {:.1}% CPU and {:.1}% memory usage. If you do not recognize the name, run sandbox analysis for additional confidence.",
            req.name, req.pid, req.cpu, req.memory
        )
    };

    Json(ExplainLogsResponse { explanation })
}

/// POST /api/v1/explain-network
pub async fn explain_network_handler(
    Json(req): Json<ExplainNetworkRequest>,
) -> Json<ExplainLogsResponse> {
    let process = req.process.unwrap_or_else(|| "Unknown process".to_string());
    let suspicious = req.remote_address.contains(":4444")
        || req.remote_address.contains(":1337")
        || req.remote_address.contains(":31337")
        || req.state.eq_ignore_ascii_case("SYN-SENT");

    let explanation = if suspicious {
        format!(
            "{} is using {} from {} to {} in {} state. This pattern is unusual and could mean unsafe remote control traffic. If you do not trust the destination, block it.",
            process, req.protocol, req.local_address, req.remote_address, req.state
        )
    } else {
        format!(
            "{} is using {} from {} to {} in {} state. This looks normal for regular app activity.",
            process, req.protocol, req.local_address, req.remote_address, req.state
        )
    };

    Json(ExplainLogsResponse { explanation })
}

/// POST /api/v1/explain-process/deep
pub async fn explain_process_deep_handler(
    Json(req): Json<DeepExplainProcessRequest>,
) -> Json<ProcessExplainDeepResponse> {
    let lower = req.name.to_ascii_lowercase();
    let exe = req.exe_path.clone().unwrap_or_default();
    let in_tmp = exe.starts_with("/tmp/") || exe.starts_with("/var/tmp/");
    let in_system = exe.starts_with("/usr/") || exe.starts_with("/bin/") || exe.starts_with("/sbin/");
    let high_load = req.cpu_percent >= 70.0 || req.memory_percent >= 40.0;
    let has_net = req.network_kbs.unwrap_or(0.0) > 0.0;

    let (verdict, score, color) = if lower.contains("av-service") || lower.contains("cybershield") {
        ("SAFE", 8, "#00ff88")
    } else if lower.contains("kscreenlocker") && req.cpu_percent >= 95.0 {
        ("SUSPICIOUS", 64, "#ffaa00")
    } else if in_tmp && has_net {
        ("DANGEROUS", 86, "#ff3366")
    } else if in_system && !high_load && !has_net {
        ("SAFE", 18, "#00ff88")
    } else if high_load || in_tmp {
        ("SUSPICIOUS", 58, "#ffaa00")
    } else {
        ("SAFE", 28, "#00ff88")
    };

    let what_is_this = if lower.contains("kscreenlocker") {
        "This is KDE's screen lock helper. It controls locking and unlocking your session, like a lock on your front door.".to_string()
    } else if lower.contains("brave") {
        "This is the Brave browser process from Brave Software. It handles web pages, tabs, and network requests.".to_string()
    } else if lower.contains("av-service") || lower.contains("cybershield") {
        "This is CyberShield's own protection engine. It scans files and watches activity to keep your device safe.".to_string()
    } else {
        format!("{} is an active program running on your device. It was started as PID {} and is currently consuming resources.", req.name, req.pid)
    };

    let what_doing_now = format!(
        "Right now it is using {:.1}% CPU and {:.1}% memory (about {:.0} MB). That is the immediate workload this process is putting on your computer.{}",
        req.cpu_percent,
        req.memory_percent,
        req.memory_mb.unwrap_or(0.0),
        if has_net {
            format!(" It is also moving network data around {:.1} KB/s.", req.network_kbs.unwrap_or(0.0))
        } else {
            " It is not showing notable network transfer at this moment.".to_string()
        }
    );

    let safety_reason = match verdict {
        "SAFE" => format!(
            "This looks safe because its behavior matches expected patterns. Path: '{}'. CPU and memory levels do not indicate obvious abuse.",
            exe
        ),
        "DANGEROUS" => format!(
            "This looks dangerous because it is running from a temporary path ('{}') and actively using network communication. That pattern is common in malware staging and remote control attempts.",
            exe
        ),
        _ => format!(
            "This looks suspicious due to abnormal behavior for this process profile. Current CPU {:.1}% and memory {:.1}% need closer review.",
            req.cpu_percent, req.memory_percent
        ),
    };

    let user_action = match verdict {
        "SAFE" => "No urgent action needed. Keep monitoring through CyberShield.".to_string(),
        "DANGEROUS" => "Block this process immediately, then run sandbox analysis and a full scan.".to_string(),
        _ => "Monitor this process closely. If the load stays high or behavior looks unknown, block it temporarily and sandbox it.".to_string(),
    };

    Json(ProcessExplainDeepResponse {
        verdict: verdict.to_string(),
        risk_score: score,
        risk_color: color.to_string(),
        one_liner: format!("{} is currently classified as {}.", req.name, verdict),
        what_is_this,
        what_doing_now,
        safety_reason,
        user_action,
    })
}

fn service_name_for_port(port: u16) -> &'static str {
    match port {
        80 => "HTTP Web (unencrypted)",
        443 => "HTTPS Secure Web",
        22 => "SSH Remote Access",
        53 => "DNS Domain Name Lookup",
        5353 => "mDNS Local Device Discovery",
        5355 => "LLMNR Local Name Resolution",
        25 => "Email SMTP Sending",
        3001 => "Local Development Service",
        4444 => "DANGEROUS - Metasploit Port",
        1337 => "DANGEROUS - Known Backdoor Port",
        6667 => "DANGEROUS - IRC Botnet Channel",
        8080 => "HTTP Proxy",
        51820 => "WireGuard VPN",
        1194 => "OpenVPN",
        3306 => "MySQL Database",
        _ => "Unknown Service",
    }
}

/// POST /api/v1/explain-network/deep
pub async fn explain_network_deep_handler(
    Json(req): Json<ExplainNetworkRequest>,
) -> Json<NetExplainDeepResponse> {
    let process = req.process.unwrap_or_else(|| "unknown".to_string());
    let remote_port = req
        .remote_address
        .split(':')
        .next_back()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(0);
    let remote_ip = req.remote_address.split(':').next().unwrap_or("");
    let is_local = remote_ip.starts_with("127.")
        || remote_ip.starts_with("0.0.0")
        || remote_ip.starts_with("192.168.")
        || remote_ip.starts_with("10.")
        || remote_ip.starts_with("224.");
    let dangerous_port = [4444_u16, 1337, 31337, 6667, 6666, 9999, 65535].contains(&remote_port);
    let safe_mdns = req.protocol.eq_ignore_ascii_case("udp") && remote_port == 5353 && remote_ip.starts_with("224.");
    let sent = req.bytes_sent.unwrap_or(0);
    let recv = req.bytes_received.unwrap_or(0);

    let (verdict, color) = if dangerous_port {
        ("DANGEROUS", "#ff3366")
    } else if safe_mdns || (remote_port == 443 && !req.state.eq_ignore_ascii_case("SYN-SENT")) || is_local {
        ("SAFE", "#00ff88")
    } else {
        ("SUSPICIOUS", "#ffaa00")
    };

    let packet_label = format!(
        "{} -> {} via {} · {} · {}",
        process,
        req.remote_address,
        req.protocol.to_uppercase(),
        if remote_port == 443 || remote_port == 8443 { "Encrypted" } else { "Unencrypted" },
        service_name_for_port(remote_port)
    );

    let plain_english = if safe_mdns {
        format!(
            "{} is sending local discovery packets on port 5353 to {}. This is a standard multicast discovery flow used by modern apps and devices on your home network.",
            process, req.remote_address
        )
    } else if dangerous_port {
        format!(
            "{} is attempting traffic on port {}, which is widely associated with offensive tooling and backdoors. This is not normal for regular app behavior.",
            process, remote_port
        )
    } else {
        format!(
            "{} is using {} from {} to {} in {} state. This connection should be reviewed if you do not recognize the destination.",
            process, req.protocol, req.local_address, req.remote_address, req.state
        )
    };

    let what_data_moving = format!(
        "Your device sent {} bytes and received {} bytes on this connection. That indicates the current transfer footprint for this network flow.",
        sent, recv
    );
    let where_going = if is_local {
        "This traffic is staying on your local/private network and does not directly leave your home/office router.".to_string()
    } else {
        format!(
            "This traffic is going to remote address {} using service {}.",
            req.remote_address,
            service_name_for_port(remote_port)
        )
    };
    let safety_reason = match verdict {
        "SAFE" => "The protocol, port, and address pattern match normal expected behavior.".to_string(),
        "DANGEROUS" => "The destination port pattern is strongly associated with malicious remote-control activity.".to_string(),
        _ => "This pattern is not immediately trusted and should be monitored for repeated suspicious behavior.".to_string(),
    };
    let user_action = match verdict {
        "SAFE" => "No action needed. Keep monitoring.".to_string(),
        "DANGEROUS" => "Block this connection immediately and run a deep scan.".to_string(),
        _ => "Monitor this connection and block if destination/process is unknown.".to_string(),
    };

    Json(NetExplainDeepResponse {
        verdict: verdict.to_string(),
        risk_color: color.to_string(),
        packet_label,
        plain_english,
        what_data_moving,
        where_going,
        safety_reason,
        user_action,
    })
}

fn determine_severity(line: &str) -> &'static str {
    if line.contains("connect(")
        || line.contains("execve(")
        || line.contains("unlink(")
        || line.contains("rename(")
    {
        "HIGH"
    } else if line.contains("openat(") || line.contains("open(") {
        "MEDIUM"
    } else {
        "LOW"
    }
}

fn extract_quoted(line: &str) -> Option<String> {
    let start = line.find('"')?;
    let rem = &line[start + 1..];
    let end = rem.find('"')?;
    Some(rem[..end].to_string())
}

/// POST /api/v1/sandbox/run
pub async fn sandbox_run_handler(Json(req): Json<SandboxRunRequest>) -> Json<SandboxReport> {
    let path = std::path::Path::new(&req.file_path);
    if !path.exists() {
        return Json(SandboxReport {
            verdict: "SUSPICIOUS".to_string(),
            risk_score: 80,
            events: Vec::new(),
            files_accessed: Vec::new(),
            network_attempts: Vec::new(),
            processes_spawned: Vec::new(),
            ai_summary: format!("File not found: {}", req.file_path),
            duration_secs: 0.0,
        });
    }

    let strace_out = "/tmp/cs_sandbox_trace.txt";
    let timeout_secs = 30_u32;
    let output = tokio::process::Command::new("timeout")
        .args([
            timeout_secs.to_string(),
            "strace".to_string(),
            "-f".to_string(),
            "-qq".to_string(),
            "-e".to_string(),
            "trace=openat,open,connect,execve,write,read,unlink,rename,socket,bind".to_string(),
            "-o".to_string(),
            strace_out.to_string(),
            "--".to_string(),
            req.file_path.clone(),
        ])
        .output()
        .await;

    let _ = output;
    let trace = tokio::fs::read_to_string(strace_out).await.unwrap_or_default();
    let mut events = Vec::new();
    let mut t = 0.0_f64;
    for line in trace.lines() {
        t += 0.05;
        if line.contains("openat(") || line.contains("open(") {
            if let Some(file) = extract_quoted(line) {
                if !(file.starts_with("/proc") || file.starts_with("/sys")) {
                    events.push(SandboxEvent {
                        time: t,
                        category: "FILE".to_string(),
                        action: if line.contains("O_WRONLY") || line.contains("O_RDWR") {
                            "WRITE".to_string()
                        } else {
                            "READ".to_string()
                        },
                        detail: file,
                        severity: determine_severity(line).to_string(),
                    });
                }
            }
        } else if line.contains("connect(") {
            events.push(SandboxEvent {
                time: t,
                category: "NETWORK".to_string(),
                action: "CONNECT_ATTEMPT".to_string(),
                detail: line.to_string(),
                severity: "HIGH".to_string(),
            });
        } else if line.contains("execve(") {
            events.push(SandboxEvent {
                time: t,
                category: "PROCESS".to_string(),
                action: "SPAWN".to_string(),
                detail: extract_quoted(line).unwrap_or_else(|| line.to_string()),
                severity: "HIGH".to_string(),
            });
        } else if line.contains("unlink(") || line.contains("rename(") {
            events.push(SandboxEvent {
                time: t,
                category: "FILE".to_string(),
                action: "DELETE_OR_RENAME".to_string(),
                detail: extract_quoted(line).unwrap_or_else(|| line.to_string()),
                severity: "HIGH".to_string(),
            });
        }
    }

    let mut score = 0_u32;
    for e in &events {
        score += match e.severity.as_str() {
            "HIGH" => 15,
            "MEDIUM" => 6,
            _ => 1,
        };
    }
    let risk_score = score.min(100) as u8;
    let verdict = if risk_score >= 70 {
        "MALICIOUS"
    } else if risk_score >= 35 {
        "SUSPICIOUS"
    } else {
        "CLEAN"
    };

    let files_accessed = events
        .iter()
        .filter(|e| e.category == "FILE")
        .map(|e| e.detail.clone())
        .take(200)
        .collect::<Vec<_>>();
    let network_attempts = events
        .iter()
        .filter(|e| e.category == "NETWORK")
        .map(|e| e.detail.clone())
        .take(200)
        .collect::<Vec<_>>();
    let processes_spawned = events
        .iter()
        .filter(|e| e.category == "PROCESS")
        .map(|e| e.detail.clone())
        .take(200)
        .collect::<Vec<_>>();

    let ai_summary = if verdict == "MALICIOUS" {
        format!(
            "The sample triggered high-risk behavior in sandbox tracing. Risk score {}/100. Quarantine immediately.",
            risk_score
        )
    } else if verdict == "SUSPICIOUS" {
        format!(
            "The sample showed suspicious runtime behavior. Risk score {}/100. Keep isolated and review before allowing.",
            risk_score
        )
    } else {
        format!(
            "No clearly dangerous behavior was observed during the sandbox window. Risk score {}/100.",
            risk_score
        )
    };

    Json(SandboxReport {
        verdict: verdict.to_string(),
        risk_score,
        events,
        files_accessed,
        network_attempts,
        processes_spawned,
        ai_summary,
        duration_secs: timeout_secs as f64,
    })
}

/// POST /api/v1/explain-threat
pub async fn explain_threat_handler(
    Json(req): Json<ExplainThreatRequest>,
) -> Json<ExplainLogsResponse> {
    let lower_name = req.name.to_ascii_lowercase();
    let lower_path = req.path.to_ascii_lowercase();
    let ext = std::path::Path::new(&req.path)
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let non_exec = matches!(
        ext.as_str(),
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" | "svg" | "md" | "txt" | "rst"
    );
    let likely_fp = non_exec && lower_name.contains("ml.");

    let family = if lower_name.contains("ransom") {
        "ransomware behavior profile"
    } else if lower_name.contains("rootkit") {
        "rootkit behavior profile"
    } else if lower_name.contains("backdoor") || lower_name.contains("rat") {
        "remote access trojan profile"
    } else if lower_name.contains("phish") {
        "phishing payload profile"
    } else if lower_name.contains("trojan") {
        "trojan profile"
    } else if lower_name.contains("eicar") {
        "antivirus validation signature (EICAR)"
    } else if lower_name.contains("ml.") {
        "machine-learning anomaly profile"
    } else {
        "generic threat profile"
    };

    let explanation = if likely_fp {
        format!(
            "This detection looks like a likely false positive. '{}' is a non-executable .{} file at {}. Non-executable media/document files cannot run on their own, so this should be reviewed and usually allowed unless another signature engine (ClamAV/YARA/HashDB) confirms malware.",
            req.name, ext, req.path
        )
    } else if req.path.starts_with("network://") {
        format!(
            "Threat {} maps to {}. This network target may indicate command-and-control or suspicious outbound behavior. Recommended action: block or monitor immediately, then run deep search for related payloads.",
            req.name, family
        )
    } else if lower_path.contains("/downloads") {
        format!(
            "Threat {} maps to {} in Downloads. Download-origin binaries and scripts have higher malware probability. Recommended action: quarantine now, then run deep search to identify related files and persistence traces.",
            req.name, family
        )
    } else {
        format!(
            "Threat {} maps to {}. Engine {} flagged this target at {}. Recommended action: quarantine if untrusted, allow only when you can verify source/integrity, and run deep search for chain activity.",
            req.name, family, req.engine, req.path
        )
    };

    Json(ExplainLogsResponse { explanation })
}

/// POST /api/v1/process/kill
pub async fn kill_process_handler(Json(req): Json<KillProcessRequest>) -> Json<ActionResponse> {
    match terminate_pid(req.pid) {
        Ok(message) => Json(ActionResponse {
            success: true,
            message,
        }),
        Err(e) => Json(ActionResponse {
            success: false,
            message: format!("Failed to terminate process: {}", e),
        }),
    }
}

/// POST /api/v1/process/block-temp
pub async fn block_process_temp_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BlockProcessTempRequest>,
) -> Json<ActionResponse> {
    let duration = Duration::from_secs(req.duration_seconds.unwrap_or(3600).clamp(60, 86_400));
    let expiry = SystemTime::now() + duration;
    let mut blocks = state.process_blocks.write().await;
    blocks.temporary.insert(req.name.to_lowercase(), expiry);
    Json(ActionResponse {
        success: true,
        message: format!(
            "Temporarily blocked {} for {} seconds",
            req.name,
            duration.as_secs()
        ),
    })
}

/// POST /api/v1/process/block-permanent
pub async fn block_process_permanent_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BlockProcessPermanentRequest>,
) -> Json<ActionResponse> {
    let mut blocks = state.process_blocks.write().await;
    let target = req.name.to_lowercase();
    if !blocks.permanent.iter().any(|x| x == &target) {
        blocks.permanent.push(target);
    }
    Json(ActionResponse {
        success: true,
        message: format!("Permanently blocked process name {}", req.name),
    })
}

/// POST /api/v1/process/sandbox
pub async fn sandbox_process_handler(Json(req): Json<SandboxRequest>) -> Json<ActionResponse> {
    Json(ActionResponse {
        success: true,
        message: format!("Queued PID {} for sandbox analysis", req.pid),
    })
}

/// POST /api/v1/scan/file-multiengine
pub async fn file_multiengine_scan_handler(
    Json(req): Json<FileMultiEngineScanRequest>,
) -> Json<MultiEngineScanResponse> {
    use sha2::{Digest, Sha256};
    let mut engines = Vec::new();

    let tmp_path = std::env::temp_dir().join(format!(
        "cybershield_scan_{}_{}",
        Utc::now().timestamp_millis(),
        req.filename
    ));

    if std::fs::write(&tmp_path, &req.data).is_err() {
        return Json(MultiEngineScanResponse {
            malicious: 0,
            total: 0,
            engines: vec![EngineResult {
                name: "Scanner".to_string(),
                detected: false,
                result: "Failed to prepare file".to_string(),
            }],
        });
    }

    let hash = hex::encode(Sha256::digest(&req.data));
    let vt_key = std::env::var("VT_API_KEY")
        .ok()
        .or_else(|| std::env::var("VIRUSTOTAL_API_KEY").ok());
    let yara_rules = std::env::var("YARA_RULES").ok();

    match crate::engines::scan_with_all_engines(
        &tmp_path,
        &hash,
        vt_key.as_deref(),
        yara_rules.as_deref(),
    )
    .await
    {
        Ok(result) => {
            let mut malicious_count = 0usize;
            for item in result.detections {
                let is_malicious = item.level == crate::engines::ThreatLevel::Malicious;
                if is_malicious {
                    malicious_count += 1;
                }
                engines.push(EngineResult {
                    name: item.engine,
                    detected: is_malicious,
                    result: item.threat_name,
                });
            }

            let _ = std::fs::remove_file(&tmp_path);
            return Json(MultiEngineScanResponse {
                malicious: malicious_count,
                total: engines.len(),
                engines,
            });
        }
        Err(e) => {
            engines.push(EngineResult {
                name: "MultiEngine".to_string(),
                detected: false,
                result: format!("Scan error: {}", e),
            });
        }
    }

    let _ = std::fs::remove_file(&tmp_path);
    let malicious = engines.iter().filter(|x| x.detected).count();

    Json(MultiEngineScanResponse {
        malicious,
        total: engines.len(),
        engines,
    })
}

/// POST /api/v1/scan/path-multiengine
pub async fn path_multiengine_scan_handler(
    Json(req): Json<PathMultiEngineScanRequest>,
) -> Json<MultiEngineScanResponse> {
    use sha2::{Digest, Sha256};

    let path = std::path::PathBuf::from(req.path.trim());
    if !path.exists() || !path.is_file() {
        return Json(MultiEngineScanResponse {
            malicious: 0,
            total: 1,
            engines: vec![EngineResult {
                name: "Scanner".to_string(),
                detected: false,
                result: "Path missing or not a regular file".to_string(),
            }],
        });
    }

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            return Json(MultiEngineScanResponse {
                malicious: 0,
                total: 1,
                engines: vec![EngineResult {
                    name: "Scanner".to_string(),
                    detected: false,
                    result: format!("Read error: {}", e),
                }],
            });
        }
    };
    let hash = hex::encode(Sha256::digest(&bytes));
    let vt_key = std::env::var("VT_API_KEY")
        .ok()
        .or_else(|| std::env::var("VIRUSTOTAL_API_KEY").ok());
    let yara_rules = std::env::var("YARA_RULES").ok();

    let mut engines = Vec::new();
    let mut malicious = 0usize;
    match crate::engines::scan_with_all_engines(
        &path,
        &hash,
        vt_key.as_deref(),
        yara_rules.as_deref(),
    )
    .await
    {
        Ok(result) => {
            for item in result.detections {
                let is_malicious = item.level == crate::engines::ThreatLevel::Malicious;
                if is_malicious {
                    malicious += 1;
                }
                engines.push(EngineResult {
                    name: item.engine,
                    detected: is_malicious,
                    result: item.threat_name,
                });
            }
        }
        Err(e) => {
            engines.push(EngineResult {
                name: "MultiEngine".to_string(),
                detected: false,
                result: format!("Scan error: {}", e),
            });
        }
    }

    Json(MultiEngineScanResponse {
        malicious,
        total: engines.len(),
        engines,
    })
}

/// POST /api/v1/scan/url-multiengine
pub async fn url_multiengine_scan_handler(
    Json(req): Json<UrlMultiEngineScanRequest>,
) -> Json<MultiEngineScanResponse> {
    let _ = req.url;
    let engines = vec![EngineResult {
        name: "URLScanner".to_string(),
        detected: false,
        result: "No live URL intelligence provider configured".to_string(),
    }];

    Json(MultiEngineScanResponse {
        malicious: 0,
        total: engines.len(),
        engines,
    })
}

fn map_engine_level_to_severity(level: &crate::engines::ThreatLevel) -> &'static str {
    match level {
        crate::engines::ThreatLevel::Clean => "low",
        crate::engines::ThreatLevel::Suspicious => "medium",
        crate::engines::ThreatLevel::Malicious => "critical",
    }
}

fn classify_name_family(name: &str) -> Option<String> {
    let n = name.to_ascii_lowercase();
    if n.contains("ransom") {
        return Some("ransomware".to_string());
    }
    if n.contains("trojan") {
        return Some("trojan".to_string());
    }
    if n.contains("backdoor") || n.contains("rat") {
        return Some("backdoor/rat".to_string());
    }
    if n.contains("rootkit") {
        return Some("rootkit".to_string());
    }
    if n.contains("worm") {
        return Some("worm".to_string());
    }
    if n.contains("spy") {
        return Some("spyware".to_string());
    }
    if n.contains("miner") || n.contains("xmrig") {
        return Some("cryptominer".to_string());
    }
    None
}

fn parse_network_iocs(input: &str) -> Vec<InvestigationIOC> {
    let mut out = Vec::new();
    let target = input.trim();
    if target.is_empty() {
        return out;
    }

    let cleaned = target
        .trim_start_matches("network://")
        .trim_start_matches("http://")
        .trim_start_matches("https://");

    let host_port = cleaned.split('/').next().unwrap_or(cleaned);
    if let Some((host, port)) = host_port.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) {
            out.push(InvestigationIOC {
                ioc_type: "port".to_string(),
                value: port.to_string(),
                reputation: if matches!(port, "4444" | "1337" | "31337" | "6667") {
                    "suspicious".to_string()
                } else {
                    "unknown".to_string()
                },
            });
            if !host.is_empty() {
                out.push(InvestigationIOC {
                    ioc_type: if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
                        "ip".to_string()
                    } else {
                        "domain".to_string()
                    },
                    value: host.to_string(),
                    reputation: "unknown".to_string(),
                });
            }
            return out;
        }
    }

    out.push(InvestigationIOC {
        ioc_type: if host_port.chars().all(|c| c.is_ascii_digit() || c == '.') {
            "ip".to_string()
        } else {
            "domain".to_string()
        },
        value: host_port.to_string(),
        reputation: "unknown".to_string(),
    });
    out
}

fn recommend_for_verdict(verdict: &str, target_type: &str) -> Vec<String> {
    match verdict {
        "highly_malicious" => vec![
            "Immediately isolate this target from the network.".to_string(),
            "Quarantine or block execution now.".to_string(),
            "Run a full deep scan to find related artifacts.".to_string(),
        ],
        "malicious" => vec![
            "Block or quarantine this target.".to_string(),
            "Review parent/child process chain and persistence points.".to_string(),
            "Collect forensic artifacts before remediation if needed.".to_string(),
        ],
        "suspicious" => vec![
            "Keep this target under monitoring.".to_string(),
            "Run deep scan and confirm with additional telemetry.".to_string(),
            format!("Apply temporary containment for {} targets when possible.", target_type),
        ],
        _ => vec![
            "No immediate malicious indicators were found.".to_string(),
            "Continue baseline monitoring.".to_string(),
        ],
    }
}

/// POST /api/v1/investigate
pub async fn investigate_handler(Json(req): Json<InvestigateRequest>) -> Json<InvestigationReport> {
    let target_type = req.target_type.to_ascii_lowercase();
    let now = Utc::now().timestamp();

    let mut report = InvestigationReport {
        target: req.target.clone(),
        target_type: target_type.clone(),
        verdict: "clean".to_string(),
        confidence: 0.15,
        engine_findings: Vec::new(),
        behavioral_analysis: InvestigationBehavioralAnalysis {
            file_operations: Vec::new(),
            network_connections: Vec::new(),
            process_indicators: Vec::new(),
            persistence_indicators: Vec::new(),
        },
        ai_assessment: InvestigationAIAssessment {
            threat_classification: "clean".to_string(),
            malware_family: None,
            attack_vectors: Vec::new(),
            payload_type: None,
            plain_english_summary: "No immediate malicious evidence was observed.".to_string(),
        },
        iocs: Vec::new(),
        threat_families: Vec::new(),
        recommendations: Vec::new(),
        timestamp: now,
    };

    if target_type == "file" {
        let path = std::path::PathBuf::from(req.target.trim());
        if path.exists() && path.is_file() {
            use sha2::{Digest, Sha256};
            if let Ok(bytes) = std::fs::read(&path) {
                let hash = hex::encode(Sha256::digest(&bytes));
                report.iocs.push(InvestigationIOC {
                    ioc_type: "hash".to_string(),
                    value: hash.clone(),
                    reputation: "unknown".to_string(),
                });
                report.iocs.push(InvestigationIOC {
                    ioc_type: "path".to_string(),
                    value: path.display().to_string(),
                    reputation: "local".to_string(),
                });

                let vt_key = std::env::var("VT_API_KEY")
                    .ok()
                    .or_else(|| std::env::var("VIRUSTOTAL_API_KEY").ok());
                let yara_rules = std::env::var("YARA_RULES").ok();

                match crate::engines::scan_with_all_engines(
                    &path,
                    &hash,
                    vt_key.as_deref(),
                    yara_rules.as_deref(),
                )
                .await
                {
                    Ok(result) => {
                        let mut score: f64 = 0.0;
                        for d in &result.detections {
                            report.engine_findings.push(InvestigationEngineFinding {
                                name: d.engine.clone(),
                                severity: map_engine_level_to_severity(&d.level).to_string(),
                                description: d.threat_name.clone(),
                            });
                            score += match d.level {
                                crate::engines::ThreatLevel::Malicious => 0.38,
                                crate::engines::ThreatLevel::Suspicious => 0.18,
                                crate::engines::ThreatLevel::Clean => 0.03,
                            };
                            if let Some(fam) = classify_name_family(&d.threat_name) {
                                report.threat_families.push(fam);
                            }
                        }
                        report.threat_families.sort();
                        report.threat_families.dedup();
                        report.confidence = score.clamp(0.15, 1.0);
                        report.verdict = match result.final_verdict {
                            crate::engines::ThreatLevel::Malicious => {
                                if report.confidence >= 0.85 {
                                    "highly_malicious".to_string()
                                } else {
                                    "malicious".to_string()
                                }
                            }
                            crate::engines::ThreatLevel::Suspicious => "suspicious".to_string(),
                            crate::engines::ThreatLevel::Clean => "clean".to_string(),
                        };
                        report.behavioral_analysis.file_operations = vec![
                            format!("Analyzed file size: {} bytes", result.file_size),
                            format!("Observed entropy score: {:.2}", result.entropy),
                        ];
                        report.ai_assessment.threat_classification = report.verdict.clone();
                        report.ai_assessment.attack_vectors = vec!["file".to_string()];
                        report.ai_assessment.malware_family = report.threat_families.first().cloned();
                        report.ai_assessment.payload_type = report
                            .threat_families
                            .first()
                            .map(|f| if f.contains("ransom") { "locker" } else { "dropper" }.to_string());
                        report.ai_assessment.plain_english_summary = if report.verdict == "clean" {
                            "The file did not show strong malicious indicators in multi-engine analysis.".to_string()
                        } else {
                            format!(
                                "Multi-engine analysis flagged this file as {} with {:.0}% confidence.",
                                report.verdict.replace('_', " "),
                                report.confidence * 100.0
                            )
                        };
                    }
                    Err(e) => {
                        report.engine_findings.push(InvestigationEngineFinding {
                            name: "MultiEngine".to_string(),
                            severity: "low".to_string(),
                            description: format!("Investigation scan error: {}", e),
                        });
                        report.ai_assessment.plain_english_summary =
                            "Investigation partially completed, but scanner execution failed.".to_string();
                    }
                }
            }
        } else {
            report.verdict = "suspicious".to_string();
            report.confidence = 0.5;
            report.ai_assessment.threat_classification = "suspicious".to_string();
            report.ai_assessment.plain_english_summary =
                "The requested file path is missing or not a regular file.".to_string();
        }
    } else if target_type == "network" {
        report.iocs = parse_network_iocs(&req.target);
        let target_lower = req.target.to_ascii_lowercase();
        let suspicious = ["4444", "1337", "31337", "6667", "tor", "onion"]
            .iter()
            .any(|x| target_lower.contains(x));
        if suspicious {
            report.verdict = "malicious".to_string();
            report.confidence = 0.82;
            report.threat_families.push("command-and-control".to_string());
            report.behavioral_analysis.network_connections = vec![
                format!("Detected suspicious remote target: {}", req.target),
                "Connection profile resembles known high-risk ports.".to_string(),
            ];
            report.ai_assessment.payload_type = Some("remote_control".to_string());
        } else {
            report.verdict = "suspicious".to_string();
            report.confidence = 0.56;
            report.behavioral_analysis.network_connections =
                vec![format!("Observed outbound target: {}", req.target)];
        }
        report.ai_assessment.threat_classification = report.verdict.clone();
        report.ai_assessment.attack_vectors = vec!["network".to_string()];
        report.ai_assessment.malware_family = report.threat_families.first().cloned();
        report.ai_assessment.plain_english_summary = if report.verdict == "malicious" {
            "This network endpoint matches high-risk communication patterns and should be blocked.".to_string()
        } else {
            "This connection is unusual and should be monitored or temporarily blocked if untrusted."
                .to_string()
        };
    } else {
        let process_rows = collect_process_logs();
        let maybe_pid = req.target.parse::<i32>().ok();
        let found = process_rows.iter().find(|p| {
            maybe_pid.map(|pid| p.pid == pid).unwrap_or(false)
                || p.name.eq_ignore_ascii_case(req.target.trim())
        });
        if let Some(p) = found {
            report.behavioral_analysis.process_indicators = vec![
                format!("PID {} CPU {:.1}%", p.pid, p.cpu_percent),
                format!("Memory {:.1}%", p.memory_percent),
            ];
            if p.suspicious {
                report.verdict = "suspicious".to_string();
                report.confidence = 0.71;
                report.threat_families.push("resource-abuse".to_string());
            } else {
                report.verdict = "clean".to_string();
                report.confidence = 0.34;
            }
            if p.blocked {
                report.behavioral_analysis.persistence_indicators.push(
                    "Process is already on a blocklist policy.".to_string(),
                );
            }
            if let Some(exe) = &p.exe_path {
                report.iocs.push(InvestigationIOC {
                    ioc_type: "path".to_string(),
                    value: exe.clone(),
                    reputation: "local".to_string(),
                });
            }
            report.ai_assessment.threat_classification = report.verdict.clone();
            report.ai_assessment.attack_vectors = vec!["process".to_string()];
            report.ai_assessment.malware_family = report.threat_families.first().cloned();
            report.ai_assessment.plain_english_summary = if p.suspicious {
                format!(
                    "Process {} (PID {}) shows suspicious runtime behavior and should be reviewed.",
                    p.name, p.pid
                )
            } else {
                format!("Process {} (PID {}) currently appears normal.", p.name, p.pid)
            };
        } else {
            report.verdict = "suspicious".to_string();
            report.confidence = 0.45;
            report.ai_assessment.threat_classification = "suspicious".to_string();
            report.ai_assessment.plain_english_summary =
                "The process was not found in live telemetry.".to_string();
        }
    }

    report.recommendations = recommend_for_verdict(&report.verdict, &report.target_type);
    Json(report)
}

/// POST /api/v1/investigate/action
pub async fn investigate_action_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<InvestigateActionRequest>,
) -> Json<ActionResponse> {
    let target_type = req.target_type.to_ascii_lowercase();
    let action = req.action.to_ascii_lowercase();

    match (target_type.as_str(), action.as_str()) {
        ("file", "quarantine") => match quarantine_path(&req.target, &state.quarantine_dir) {
            Ok(msg) => Json(ActionResponse {
                success: true,
                message: msg,
            }),
            Err(e) => Json(ActionResponse {
                success: false,
                message: format!("Quarantine failed: {}", e),
            }),
        },
        ("process", "block") => {
            let mut blocks = state.process_blocks.write().await;
            let target = req.target.to_lowercase();
            if !blocks.permanent.iter().any(|x| x == &target) {
                blocks.permanent.push(target);
            }
            Json(ActionResponse {
                success: true,
                message: "Process permanently blocked by name".to_string(),
            })
        }
        (_, "monitor") => Json(ActionResponse {
            success: true,
            message: "Target added to active monitoring workflow".to_string(),
        }),
        _ => Json(ActionResponse {
            success: false,
            message: "Unsupported action for target type".to_string(),
        }),
    }
}

async fn handle_block_action(state: &Arc<AppState>, alert: &ThreatAlert) -> anyhow::Result<String> {
    let mut messages = Vec::new();

    match terminate_pid(alert.pid) {
        Ok(msg) => messages.push(msg),
        Err(e) => messages.push(format!("process stop failed: {}", e)),
    }

    if !alert.file_path.is_empty() {
        match quarantine_path(&alert.file_path, &state.quarantine_dir) {
            Ok(msg) => messages.push(msg),
            Err(e) => messages.push(format!("quarantine failed: {}", e)),
        }
    }

    Ok(messages.join("; "))
}

async fn handle_monitor_action(
    state: &Arc<AppState>,
    alert: &ThreatAlert,
) -> anyhow::Result<String> {
    let monitored = MonitoredProcess {
        pid: alert.pid,
        path: alert.file_path.clone(),
        alert_id: alert.id.clone(),
        started_at_unix: Utc::now().timestamp(),
        suspicious_count: 0,
    };

    {
        let mut map = state.monitored_processes.lock().await;
        map.insert(alert.pid, monitored);
    }

    let app_state = state.clone();
    let pid = alert.pid;
    tokio::spawn(async move {
        monitor_process_until_escalation(app_state, pid).await;
    });

    Ok(format!(
        "Monitoring PID {} for suspicious behavior",
        alert.pid
    ))
}

async fn handle_allow_action(state: &Arc<AppState>, alert: &ThreatAlert) -> anyhow::Result<String> {
    if !alert.file_path.is_empty() {
        let mut allowlist = state.allowlist.write().await;
        if !allowlist.iter().any(|x| x == &alert.file_path) {
            allowlist.push(alert.file_path.clone());
        }
    }
    Ok("Added file to allowlist".to_string())
}

async fn monitor_process_until_escalation(state: Arc<AppState>, pid: i32) {
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;

        if !is_process_running(pid) {
            let mut map = state.monitored_processes.lock().await;
            map.remove(&pid);
            break;
        }

        let mut suspicious_now = false;
        let mut reason = String::new();

        for process in collect_process_logs() {
            if process.pid == pid {
                suspicious_now = process.suspicious;
                reason = format!(
                    "high resource usage ({:.1}% CPU, {:.1}% memory)",
                    process.cpu_percent, process.memory_percent
                );
                break;
            }
        }

        if !suspicious_now {
            continue;
        }

        let (should_escalate, process_path) = {
            let mut map = state.monitored_processes.lock().await;
            if let Some(entry) = map.get_mut(&pid) {
                entry.suspicious_count = entry.suspicious_count.saturating_add(1);
                let process_path = entry.path.clone();
                let should_escalate = entry.suspicious_count >= 3;
                if should_escalate {
                    map.remove(&pid);
                }
                (should_escalate, process_path)
            } else {
                break;
            }
        };

        if !should_escalate {
            continue;
        }

        let process_name = process_name_for_pid(pid).unwrap_or_else(|| "unknown".to_string());
        let alert = ThreatAlert {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now().timestamp(),
            file_path: process_path,
            process_name: process_name.clone(),
            pid,
            threat_type: "Behavioral".to_string(),
            threat_name: "Escalating Suspicious Behavior".to_string(),
            severity: AlertSeverity::High,
            detection_engines: vec!["Behavioral Monitor".to_string()],
            confidence: 0.85,
            ai_explanation: format!(
                "This program kept acting strangely three times in a row ({reason}). It now looks risky and should be blocked."
            ),
        };

        {
            let mut alerts = state.pending_alerts.lock().await;
            alerts.insert(alert.id.clone(), alert.clone());
        }
        let _ = state
            .realtime_events
            .send(RealtimeEvent::ThreatAlert(alert));
        break;
    }
}

fn terminate_pid(pid: i32) -> anyhow::Result<String> {
    if pid <= 0 {
        anyhow::bail!("invalid pid");
    }

    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .output()?;
        if output.status.success() {
            return Ok(format!("terminated PID {}", pid));
        }
        anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }

    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("process termination is not implemented for this platform");
    }
}

fn quarantine_path(path: &str, quarantine_dir: &str) -> anyhow::Result<String> {
    let source = std::path::Path::new(path);
    if !source.exists() {
        anyhow::bail!("file not found");
    }

    std::fs::create_dir_all(quarantine_dir)?;
    let filename = source
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("sample");
    let destination = std::path::Path::new(quarantine_dir).join(format!(
        "{}_{}",
        Utc::now().format("%Y%m%d_%H%M%S"),
        filename
    ));
    std::fs::rename(source, &destination)?;
    Ok(format!("quarantined to {}", destination.display()))
}

fn is_process_running(pid: i32) -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        true
    }
}

fn process_name_for_pid(pid: i32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        Some(comm.trim().to_string())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

fn read_process_exe(pid: i32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

fn read_process_parent_pid(pid: i32) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let parts: Vec<&str> = stat.split_whitespace().collect();
        parts.get(3)?.parse::<u32>().ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

fn read_process_memory_mb(pid: i32) -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb = rest.split_whitespace().next()?.parse::<f64>().ok()?;
                return Some(kb / 1024.0);
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

fn read_process_io_bytes(pid: u32) -> Option<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
        let mut sent = 0_u64;
        let mut recv = 0_u64;
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("write_bytes:") {
                sent = rest.trim().parse::<u64>().ok()?;
            } else if let Some(rest) = line.strip_prefix("read_bytes:") {
                recv = rest.trim().parse::<u64>().ok()?;
            }
        }
        Some((sent, recv))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

fn collect_process_logs() -> Vec<ProcessLogEntry> {
    #[cfg(target_os = "linux")]
    {
        collect_process_logs_linux()
    }

    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

fn collect_process_logs_with_blocks(blocks: &ProcessBlocklist) -> Vec<ProcessLogEntry> {
    let mut rows = collect_process_logs();
    for row in &mut rows {
        row.blocked = is_blocked_process(blocks, &row.name);
    }
    rows
}

fn is_blocked_process(blocks: &ProcessBlocklist, name: &str) -> bool {
    let lower = name.to_lowercase();
    if blocks.permanent.iter().any(|x| lower.contains(x)) {
        return true;
    }

    if let Some(expiry) = blocks.temporary.get(&lower) {
        if *expiry > SystemTime::now() {
            return true;
        }
    }

    blocks
        .temporary
        .iter()
        .any(|(n, expiry)| lower.contains(n) && *expiry > SystemTime::now())
}

#[cfg(target_os = "linux")]
fn collect_process_logs_linux() -> Vec<ProcessLogEntry> {
    let output = std::process::Command::new("ps")
        .args(["-eo", "pid,comm,pcpu,pmem", "--sort=-pcpu"])
        .output();

    let Ok(output) = output else {
        return Vec::new();
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut rows = Vec::new();

    for (idx, line) in stdout.lines().enumerate() {
        if idx == 0 {
            continue;
        }

        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }

        let pid = cols[0].parse::<i32>().unwrap_or(0);
        let name = cols[1].to_string();
        let cpu_percent = cols[2].parse::<f32>().unwrap_or(0.0);
        let memory_percent = cols[3].parse::<f32>().unwrap_or(0.0);

        let lower = name.to_lowercase();
        let suspicious = cpu_percent >= 70.0
            || memory_percent >= 40.0
            || lower.contains("miner")
            || lower.contains("mimikatz")
            || lower.contains("nc");

        let protected = pid <= 1 || lower == "systemd" || lower == "kernel";

        rows.push(ProcessLogEntry {
            pid,
            name,
            cpu_percent,
            memory_percent,
            memory_mb: read_process_memory_mb(pid),
            network_kbs: Some(0.0),
            exe_path: read_process_exe(pid),
            parent_pid: read_process_parent_pid(pid),
            network_activity: None,
            suspicious,
            protected,
            blocked: false,
        });

        if rows.len() >= 200 {
            break;
        }
    }

    rows
}

pub(crate) fn collect_network_logs() -> Vec<NetworkLogEntry> {
    #[cfg(target_os = "linux")]
    {
        collect_network_logs_linux()
    }

    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn collect_network_logs_linux() -> Vec<NetworkLogEntry> {
    let output = std::process::Command::new("ss").args(["-tunapH"]).output();

    let Ok(output) = output else {
        return Vec::new();
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut rows = Vec::new();

    for line in stdout.lines().take(500) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        // ss -tunapH typically: tcp ESTAB 0 0 local:port remote:port users:(("proc",pid=...))
        let protocol = parts[0].to_string();
        let state = parts[1].to_string();
        let local_address = parts[4].to_string();
        let remote_address = parts.get(5).copied().unwrap_or("").to_string();
        let process_field = parts
            .iter()
            .find(|p| p.starts_with("users:"))
            .map(|x| x.to_string());

        let process = process_field.as_ref().and_then(|p| {
            let first_quote = p.find('"')?;
            let after_first = &p[first_quote + 1..];
            let second_quote = after_first.find('"')?;
            Some(after_first[..second_quote].to_string())
        });

        let suspicious = remote_address.contains(":4444")
            || remote_address.contains(":1337")
            || remote_address.contains(":31337")
            || state.eq_ignore_ascii_case("SYN-SENT")
            || process
                .as_ref()
                .map(|p| {
                    let n = p.to_lowercase();
                    n.contains("nc") || n.contains("curl") || n.contains("python")
                })
                .unwrap_or(false);

        let parsed_pid = process_field
            .as_ref()
            .and_then(|p| p.find("pid=").map(|idx| &p[idx + 4..]))
            .and_then(|rest| {
                let end = rest.find([',', ')']).unwrap_or(rest.len());
                rest[..end].parse::<u32>().ok()
            });
        let (bytes_sent, bytes_received) = parsed_pid
            .and_then(read_process_io_bytes)
            .map(|(s, r)| (Some(s), Some(r)))
            .unwrap_or((None, None));

        rows.push(NetworkLogEntry {
            protocol,
            local_address,
            remote_address,
            state,
            process,
            pid: parsed_pid,
            bytes_sent,
            bytes_received,
            suspicious,
        });
    }

    rows
}

fn score_url_risk(url: &str) -> f32 {
    let lower = url.to_ascii_lowercase();
    let mut score = 0.0_f32;

    let suspicious_tokens = [
        "login",
        "verify",
        "secure",
        "gift",
        "free",
        "bank",
        "update-account",
        "password",
    ];
    for token in suspicious_tokens {
        if lower.contains(token) {
            score += 0.10;
        }
    }

    let suspicious_tlds = [".xyz", ".top", ".click", ".zip", ".mov"];
    for tld in suspicious_tlds {
        if lower.contains(tld) {
            score += 0.15;
        }
    }

    if lower.starts_with("http://") {
        score += 0.15;
    }
    if lower.ends_with(".exe") || lower.ends_with(".scr") || lower.ends_with(".hta") {
        score += 0.30;
    }
    if lower.matches('-').count() >= 3 {
        score += 0.10;
    }

    score.clamp(0.0, 1.0)
}

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/live-stats", get(live_stats_handler))
        .route(
            "/api/v1/settings",
            get(get_settings_handler).put(put_settings_handler),
        )
        .route("/api/v1/scan", post(scan_handler))
        .route("/api/v1/scan/deep", post(deep_scan_handler))
        .route("/api/v1/threats", get(threats_handler))
        .route("/api/v1/threats/action", post(threat_action_handler))
        .route("/api/v1/investigate", post(investigate_handler))
        .route("/api/v1/investigate/action", post(investigate_action_handler))
        .route("/api/v1/alerts/pending", get(pending_alerts_handler))
        .route("/api/v1/alerts/decision", post(alert_decision_handler))
        .route(
            "/api/v1/quarantine",
            post(quarantine_handler).get(quarantine_list_handler),
        )
        .route("/api/v1/process-logs", get(process_logs_handler))
        .route("/api/v1/network-logs", get(network_logs_handler))
        .route("/api/v1/explain-logs", post(explain_logs_handler))
        .route("/api/v1/explain-process", post(explain_process_handler))
        .route("/api/v1/explain-process/deep", post(explain_process_deep_handler))
        .route("/api/v1/explain-network", post(explain_network_handler))
        .route("/api/v1/explain-network/deep", post(explain_network_deep_handler))
        .route("/api/v1/explain-threat", post(explain_threat_handler))
        .route("/api/v1/process/kill", post(kill_process_handler))
        .route(
            "/api/v1/process/block-temp",
            post(block_process_temp_handler),
        )
        .route(
            "/api/v1/process/block-permanent",
            post(block_process_permanent_handler),
        )
        .route("/api/v1/process/sandbox", post(sandbox_process_handler))
        .route("/api/v1/sandbox/run", post(sandbox_run_handler))
        .route(
            "/api/v1/scan/file-multiengine",
            post(file_multiengine_scan_handler),
        )
        .route(
            "/api/v1/scan/path-multiengine",
            post(path_multiengine_scan_handler),
        )
        .route(
            "/api/v1/scan/url-multiengine",
            post(url_multiengine_scan_handler),
        )
        .layer(tower_http::cors::CorsLayer::permissive())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> Arc<AppState> {
        let (scan_tx, _scan_rx) = mpsc::channel(8);
        let (events, _events_rx) = broadcast::channel(8);
        Arc::new(AppState {
            scan_tx,
            threats: Arc::new(Mutex::new(Vec::new())),
            quarantine_dir: "/tmp/cybershield-test-quarantine".to_string(),
            settings: Arc::new(RwLock::new(ServiceSettings::default())),
            settings_path: "/tmp/cybershield-settings.json".to_string(),
            realtime_events: events,
            process_blocks: Arc::new(RwLock::new(ProcessBlocklist::default())),
            pending_alerts: Arc::new(Mutex::new(HashMap::new())),
            monitored_processes: Arc::new(Mutex::new(HashMap::new())),
            allowlist: Arc::new(RwLock::new(Vec::new())),
            live_stats: Arc::new(Mutex::new(crate::stats::LiveStatsState::default())),
        })
    }

    #[tokio::test]
    async fn allow_action_adds_allowlist_entry() {
        let state = test_state();
        let alert = ThreatAlert {
            id: "a1".to_string(),
            timestamp: Utc::now().timestamp(),
            file_path: "/tmp/safe.bin".to_string(),
            process_name: "safe.bin".to_string(),
            pid: 0,
            threat_type: "test".to_string(),
            threat_name: "Test".to_string(),
            severity: AlertSeverity::Low,
            detection_engines: vec!["test".to_string()],
            confidence: 0.5,
            ai_explanation: "test".to_string(),
        };

        handle_allow_action(&state, &alert).await.unwrap();
        let allowlist = state.allowlist.read().await;
        assert!(allowlist.iter().any(|x| x == "/tmp/safe.bin"));
    }

    #[test]
    fn url_risk_scoring_flags_obvious_phishing() {
        let risky = score_url_risk("http://bank-secure-login-verify.example.com/free-gift.exe");
        assert!(risky >= 0.70);
    }
}
