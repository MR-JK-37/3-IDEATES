import { invoke } from '@tauri-apps/api/tauri';

export type ProtectionStatus = { is_protected?: boolean; last_scan?: string };
export type Threat = {
  id: string;
  name: string;
  path: string;
  severity: string;
  timestamp: string;
  engine?: string;
  action: string;
  details?: string;
};

export type ProcessLogEntry = {
  pid: number;
  name: string;
  cpu_percent: number;
  memory_percent: number;
  memory_mb?: number;
  network_kbs?: number;
  exe_path?: string | null;
  parent_pid?: number;
  network_activity?: string | null;
  suspicious: boolean;
  protected: boolean;
  blocked?: boolean;
};

export type NetworkLogEntry = {
  protocol: string;
  local_address: string;
  remote_address: string;
  state: string;
  process?: string | null;
  pid?: number | null;
  bytes_sent?: number | null;
  bytes_received?: number | null;
  suspicious: boolean;
};

export type ProcessExplainDeepResult = {
  verdict: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
  risk_score: number;
  risk_color: string;
  one_liner: string;
  what_is_this: string;
  what_doing_now: string;
  safety_reason: string;
  user_action: string;
};

export type NetExplainDeepResult = {
  verdict: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
  risk_color: string;
  packet_label: string;
  plain_english: string;
  what_data_moving: string;
  where_going: string;
  safety_reason: string;
  user_action: string;
};

export type SandboxEvent = {
  time: number;
  category: string;
  action: string;
  detail: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
};

export type SandboxReport = {
  verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS';
  risk_score: number;
  events: SandboxEvent[];
  files_accessed: string[];
  network_attempts: string[];
  processes_spawned: string[];
  ai_summary: string;
  duration_secs: number;
};

export type ProcessExplainRequest = {
  pid: number;
  name: string;
  cpu: number;
  memory: number;
};

export type NetworkExplainRequest = {
  protocol: string;
  local_address: string;
  remote_address: string;
  state: string;
  process?: string | null;
};

export type ThreatExplainRequest = {
  id: string;
  name: string;
  path: string;
  severity: string;
  engine: string;
  action: string;
};

export type EngineResult = {
  name: string;
  detected: boolean;
  result: string;
};

export type MultiEngineScanResult = {
  malicious: number;
  total: number;
  engines: EngineResult[];
};

export type ThreatAlert = {
  id: string;
  timestamp: number;
  file_path: string;
  process_name: string;
  pid: number;
  threat_type: string;
  threat_name: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  detection_engines: string[];
  confidence: number;
  ai_explanation: string;
};

export type DashboardStats = {
  threatsBlocked: number;
  lastScan: string;
  engineVersion: string;
  cpuUsage: number;
  memoryUsage: number;
};

export type AppSettings = {
  realTimeProtection: boolean;
  autoScan: boolean;
  scanInterval: number;
  quarantineEnabled: boolean;
  notificationsEnabled: boolean;
  reportingEnabled: boolean;
  excludePaths: string;
  threatActions: 'block' | 'quarantine' | 'alert';
  autoUpload: boolean;
};

export type LiveMonitorStatus = {
  name: string;
  active: boolean;
  events_count: number;
};

export type LiveScanStats = {
  files_per_sec: number;
  events_per_sec: number;
  total_scanned: number;
  threats_today: number;
  threats_total: number;
  monitors_active: LiveMonitorStatus[];
  av_cpu: number;
  av_ram_mb: number;
  scan_progress_percent: number;
  uptime_secs: number;
  last_scan_file: string;
};

export type ServiceSettings = {
  realTimeProtection: boolean;
  autoScan: boolean;
  scanIntervalHours: number;
  quarantineEnabled: boolean;
};

export type BackendHealth = {
  online: boolean;
  source: 'service-http' | 'tauri-ipc' | 'offline';
  message?: string;
};

export type ToggleStatus = {
  enabled: boolean;
  message?: string;
};

export type InvestigationEngineFinding = {
  name: string;
  severity: string;
  description: string;
};

export type InvestigationIOC = {
  iocType: string;
  value: string;
  reputation: string;
};

export type InvestigationBehavioralAnalysis = {
  fileOperations: string[];
  networkConnections: string[];
  processIndicators: string[];
  persistenceIndicators: string[];
};

export type InvestigationAIAssessment = {
  threatClassification: string;
  malwareFamily?: string | null;
  attackVectors: string[];
  payloadType?: string | null;
  plainEnglishSummary: string;
};

export type InvestigationReport = {
  target: string;
  targetType: 'network' | 'file' | 'process' | string;
  verdict: 'clean' | 'suspicious' | 'malicious' | 'highly_malicious' | string;
  confidence: number;
  engineFindings: InvestigationEngineFinding[];
  behavioralAnalysis: InvestigationBehavioralAnalysis;
  aiAssessment: InvestigationAIAssessment;
  iocs: InvestigationIOC[];
  threatFamilies: string[];
  recommendations: string[];
  timestamp: number;
};

type InvestigationReportWire = Partial<InvestigationReport> & {
  target_type?: string;
  engine_findings?: InvestigationEngineFinding[];
  behavioral_analysis?: InvestigationBehavioralAnalysis;
  ai_assessment?: InvestigationAIAssessment;
  threat_families?: string[];
};

const SETTINGS_STORAGE_KEY = 'cybershield-ui-settings';
const DEFAULT_SERVICE_BASE_URL = 'http://127.0.0.1:3001';
const HTTP_TIMEOUT_MS = 1800;

const defaultStats: DashboardStats = {
  threatsBlocked: 0,
  lastScan: '',
  engineVersion: '',
  cpuUsage: 0,
  memoryUsage: 0,
};

const defaultSettings: AppSettings = {
  realTimeProtection: true,
  autoScan: true,
  scanInterval: 24,
  quarantineEnabled: true,
  notificationsEnabled: true,
  reportingEnabled: true,
  excludePaths: '/System,/Library',
  threatActions: 'block',
  autoUpload: true,
};

function isTauriRuntime(): boolean {
  return typeof window !== 'undefined' && '__TAURI_IPC__' in (window as unknown as Record<string, unknown>);
}

function serviceBaseUrl(): string {
  const envUrl = (import.meta as ImportMeta & { env?: Record<string, string> }).env?.VITE_AV_SERVICE_URL?.trim();
  const local = window.localStorage.getItem('cybershield-service-url')?.trim();
  if (envUrl) return envUrl;
  if (local) return local;
  // Default av-service bind for desktop/dev.
  return DEFAULT_SERVICE_BASE_URL;
}

function serviceUrl(path: string): string {
  return `${serviceBaseUrl()}${path}`;
}

async function httpJson<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);
  try {
    const response = await fetch(serviceUrl(path), {
      ...init,
      headers: {
        'Content-Type': 'application/json',
        ...(init?.headers ?? {}),
      },
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} for ${path}`);
    }
    return (await response.json()) as T;
  } finally {
    window.clearTimeout(timer);
  }
}

async function ipc<T>(command: string, payload?: Record<string, unknown>): Promise<T> {
  if (!isTauriRuntime()) {
    throw new Error('CyberShield backend is available only inside Tauri runtime');
  }
  return invoke<T>(command, payload);
}

function throwServiceUnavailable(path: string, cause: unknown): never {
  throw new Error(
    `Cannot reach av-service endpoint ${path} at ${serviceBaseUrl()}. Start av-service on port 3001 or set VITE_AV_SERVICE_URL. Details: ${String(cause)}`
  );
}

export async function getBackendHealth(): Promise<BackendHealth> {
  try {
    const status = await httpJson<{ status?: string; version?: string }>('/api/v1/status');
    return {
      online: status?.status === 'ok',
      source: 'service-http',
      message: status?.version ? `av-service ${status.version}` : 'av-service reachable',
    };
  } catch (httpErr) {
    if (isTauriRuntime()) {
      try {
        await ipc<ProtectionStatus>('get_protection_status');
        return {
          online: true,
          source: 'tauri-ipc',
          message: `HTTP unreachable (${String(httpErr)}), using Tauri IPC`,
        };
      } catch (ipcErr) {
        return {
          online: false,
          source: 'offline',
          message: `HTTP error: ${String(httpErr)} | IPC error: ${String(ipcErr)}`,
        };
      }
    }
    return {
      online: false,
      source: 'offline',
      message: String(httpErr),
    };
  }
}

export async function getProtectionStatus(): Promise<ProtectionStatus> {
  try {
    const status = await httpJson<{
      protection_active?: boolean;
      realtime_enabled?: boolean;
      status?: string;
      version?: string;
    }>('/api/v1/status');
    return {
      is_protected: Boolean(status?.protection_active ?? status?.realtime_enabled),
      last_scan: status?.version ? `Engine ${status.version}` : 'Service healthy',
    };
  } catch {
    return ipc<ProtectionStatus>('get_protection_status');
  }
}

export async function getRecentThreats(): Promise<Threat[]> {
  try {
    return await httpJson<Threat[]>('/api/v1/threats');
  } catch {
    return ipc<Threat[]>('get_recent_threats');
  }
}

export async function getSystemStats(): Promise<DashboardStats> {
  try {
    const [statusData, liveData] = await Promise.all([
      httpJson<{
        status?: string;
        version?: string;
        protection_active?: boolean;
      }>('/api/v1/status'),
      httpJson<{
        data?: {
          threats_total?: number;
          av_cpu?: number;
          av_ram_mb?: number;
          last_scan_file?: string;
        };
      }>('/api/v1/live-stats'),
    ]);

    const live = liveData?.data;
    return {
      threatsBlocked: live?.threats_total ?? 0,
      lastScan: live?.last_scan_file ? `Scanned: ${live.last_scan_file}` : '',
      engineVersion: statusData?.version ?? '',
      cpuUsage: live?.av_cpu ?? 0,
      memoryUsage: live?.av_ram_mb ?? 0,
    };
  } catch {
    const statsData = await ipc<{
      threats_blocked?: number;
      last_scan?: string;
      engine_version?: string;
      cpu_usage?: number;
      memory_usage?: number;
    }>('get_system_stats');

    return {
      threatsBlocked: statsData?.threats_blocked ?? 0,
      lastScan: statsData?.last_scan ?? '',
      engineVersion: statsData?.engine_version ?? '',
      cpuUsage: statsData?.cpu_usage ?? 0,
      memoryUsage: statsData?.memory_usage ?? 0,
    };
  }
}

export async function runScan(path: string): Promise<{ verdict: string }> {
  try {
    const scanResult = await httpJson<{ verdict?: string }>('/api/v1/scan', {
      method: 'POST',
      body: JSON.stringify({ path }),
    });
    return { verdict: scanResult?.verdict ?? 'Scanning' };
  } catch {
    const scanResult = await ipc<{ verdict?: string }>('invoke_scan', { path });
    return { verdict: scanResult?.verdict ?? 'Scanning' };
  }
}

export async function runDeepSearch(
  rootPath?: string,
  maxFiles = 2500
): Promise<{ root_path: string; queued_files: number; timestamp: string }> {
  try {
    return await httpJson<{ root_path: string; queued_files: number; timestamp: string }>(
      '/api/v1/scan/deep',
      {
        method: 'POST',
        body: JSON.stringify({
          root_path: rootPath,
          max_files: maxFiles,
        }),
      }
    );
  } catch {
    return ipc<{ root_path: string; queued_files: number; timestamp: string }>('run_deep_search', {
      root_path: rootPath,
      max_files: maxFiles,
    });
  }
}

export async function getAppSettings(): Promise<AppSettings> {
  try {
    const settings = await httpJson<{
      real_time_protection?: boolean;
      auto_scan?: boolean;
      scan_interval_hours?: number;
      quarantine_enabled?: boolean;
    }>('/api/v1/settings');

    return {
      ...defaultSettings,
      realTimeProtection: settings.real_time_protection ?? defaultSettings.realTimeProtection,
      autoScan: settings.auto_scan ?? defaultSettings.autoScan,
      scanInterval: settings.scan_interval_hours ?? defaultSettings.scanInterval,
      quarantineEnabled: settings.quarantine_enabled ?? defaultSettings.quarantineEnabled,
    };
  } catch {
    try {
      const settings = await ipc<AppSettings>('get_app_settings');
      return { ...defaultSettings, ...settings };
    } catch {
      // Fall through to local storage.
    }
  }

  const raw = window.localStorage.getItem(SETTINGS_STORAGE_KEY);
  if (!raw) return defaultSettings;

  try {
    const parsed = JSON.parse(raw) as Partial<AppSettings>;
    return { ...defaultSettings, ...parsed };
  } catch {
    return defaultSettings;
  }
}

export async function saveAppSettings(settings: AppSettings): Promise<AppSettings> {
  try {
    await httpJson('/api/v1/settings', {
      method: 'PUT',
      body: JSON.stringify({
        real_time_protection: settings.realTimeProtection,
        auto_scan: settings.autoScan,
        scan_interval_hours: settings.scanInterval,
        quarantine_enabled: settings.quarantineEnabled,
      }),
    });
  } catch {
    try {
      await ipc<AppSettings>('save_app_settings', { settings });
    } catch {
      // Continue with local storage fallback.
    }
  }

  window.localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(settings));
  return { ...defaultSettings, ...settings };
}

export async function toggleRealtimeProtection(enabled: boolean): Promise<ToggleStatus> {
  try {
    const current = await getAppSettings();
    await saveAppSettings({ ...current, realTimeProtection: enabled });
    return {
      enabled,
      message: enabled ? 'Real-time protection enabled' : 'Real-time protection disabled',
    };
  } catch {
    return ipc<ToggleStatus>('toggle_realtime_protection', { enabled });
  }
}

export async function getRealtimeProtectionStatus(): Promise<ToggleStatus> {
  try {
    const current = await getAppSettings();
    return { enabled: Boolean(current.realTimeProtection) };
  } catch {
    return ipc<ToggleStatus>('get_realtime_protection_status');
  }
}

export async function toggleAutostart(enabled: boolean): Promise<ToggleStatus> {
  if (!isTauriRuntime()) {
    return {
      enabled: false,
      message: 'Autostart can be managed only in desktop runtime.',
    };
  }
  return ipc<ToggleStatus>('toggle_autostart', { enabled });
}

export async function getAutostartStatus(): Promise<ToggleStatus> {
  try {
    return ipc<ToggleStatus>('get_autostart_status');
  } catch {
    return { enabled: false, message: 'Autostart status unavailable outside desktop runtime' };
  }
}

export async function getProcessLogs(): Promise<ProcessLogEntry[]> {
  try {
    return await httpJson<ProcessLogEntry[]>('/api/v1/process-logs');
  } catch {
    return ipc<ProcessLogEntry[]>('get_process_logs');
  }
}

export async function getNetworkLogs(): Promise<NetworkLogEntry[]> {
  try {
    return await httpJson<NetworkLogEntry[]>('/api/v1/network-logs');
  } catch {
    return ipc<NetworkLogEntry[]>('get_network_logs');
  }
}

export async function explainLogs(kind: 'process' | 'network'): Promise<string> {
  try {
    const response = await httpJson<{ explanation: string }>('/api/v1/explain-logs', {
      method: 'POST',
      body: JSON.stringify({ kind }),
    });
    return response.explanation;
  } catch (httpErr) {
    if (!isTauriRuntime()) {
      throwServiceUnavailable('/api/v1/explain-logs', httpErr);
    }
    const response = await ipc<{ explanation: string }>('explain_logs', { kind });
    return response.explanation;
  }
}

export async function explainProcess(entry: ProcessExplainRequest): Promise<string> {
  try {
    const response = await httpJson<{ explanation: string }>('/api/v1/explain-process', {
      method: 'POST',
      body: JSON.stringify(entry),
    });
    return response.explanation;
  } catch (httpErr) {
    if (!isTauriRuntime()) {
      throwServiceUnavailable('/api/v1/explain-process', httpErr);
    }
    const response = await ipc<{ explanation: string }>('explain_process_entry', { entry });
    return response.explanation;
  }
}

export async function explainNetwork(entry: NetworkExplainRequest): Promise<string> {
  try {
    const response = await httpJson<{ explanation: string }>('/api/v1/explain-network', {
      method: 'POST',
      body: JSON.stringify(entry),
    });
    return response.explanation;
  } catch (httpErr) {
    if (!isTauriRuntime()) {
      throwServiceUnavailable('/api/v1/explain-network', httpErr);
    }
    const response = await ipc<{ explanation: string }>('explain_network_entry', { entry });
    return response.explanation;
  }
}

export async function explainThreat(entry: ThreatExplainRequest): Promise<string> {
  try {
    const response = await httpJson<{ explanation: string }>('/api/v1/explain-threat', {
      method: 'POST',
      body: JSON.stringify(entry),
    });
    return response.explanation;
  } catch (httpErr) {
    if (!isTauriRuntime()) {
      throwServiceUnavailable('/api/v1/explain-threat', httpErr);
    }
    const response = await ipc<{ explanation: string }>('explain_threat_entry', { entry });
    return response.explanation;
  }
}

export async function deepExplainProcess(entry: {
  pid: number;
  name: string;
  cpu_percent: number;
  memory_percent: number;
  memory_mb?: number;
  network_kbs?: number;
  exe_path?: string;
  parent_pid?: number;
}): Promise<ProcessExplainDeepResult> {
  try {
    return await httpJson<ProcessExplainDeepResult>('/api/v1/explain-process/deep', {
      method: 'POST',
      body: JSON.stringify(entry),
    });
  } catch (httpErr) {
    if (!isTauriRuntime()) {
      throwServiceUnavailable('/api/v1/explain-process/deep', httpErr);
    }
    return ipc<ProcessExplainDeepResult>('deep_explain_process', { entry });
  }
}

export async function deepExplainConnection(entry: {
  protocol: string;
  local_address: string;
  remote_address: string;
  state: string;
  process?: string | null;
  pid?: number | null;
  bytes_sent?: number | null;
  bytes_received?: number | null;
}): Promise<NetExplainDeepResult> {
  try {
    return await httpJson<NetExplainDeepResult>('/api/v1/explain-network/deep', {
      method: 'POST',
      body: JSON.stringify(entry),
    });
  } catch (httpErr) {
    if (!isTauriRuntime()) {
      throwServiceUnavailable('/api/v1/explain-network/deep', httpErr);
    }
    return ipc<NetExplainDeepResult>('deep_explain_connection', { entry });
  }
}

export async function runSandbox(filePath: string): Promise<SandboxReport> {
  try {
    return await httpJson<SandboxReport>('/api/v1/sandbox/run', {
      method: 'POST',
      body: JSON.stringify({ file_path: filePath }),
    });
  } catch (httpErr) {
    if (!isTauriRuntime()) {
      throwServiceUnavailable('/api/v1/sandbox/run', httpErr);
    }
    return ipc<SandboxReport>('run_sandbox', { file_path: filePath });
  }
}

export async function killProcess(pid: number): Promise<{ success: boolean; message: string }> {
  try {
    return await httpJson<{ success: boolean; message: string }>('/api/v1/process/kill', {
      method: 'POST',
      body: JSON.stringify({ pid }),
    });
  } catch (httpErr) {
    if (!isTauriRuntime()) {
      throwServiceUnavailable('/api/v1/process/kill', httpErr);
    }
    return ipc<{ success: boolean; message: string }>('kill_process_cmd', { pid });
  }
}

export async function blockProcessTemp(
  name: string,
  durationSeconds = 3600
): Promise<{ success: boolean; message: string }> {
  try {
    return await httpJson<{ success: boolean; message: string }>('/api/v1/process/block-temp', {
      method: 'POST',
      body: JSON.stringify({
        name,
        duration_seconds: durationSeconds,
      }),
    });
  } catch (httpErr) {
    if (!isTauriRuntime()) {
      throwServiceUnavailable('/api/v1/process/block-temp', httpErr);
    }
    return ipc<{ success: boolean; message: string }>('block_process_temp_cmd', {
      name,
      duration_seconds: durationSeconds,
    });
  }
}

export async function blockProcessPermanent(
  name: string
): Promise<{ success: boolean; message: string }> {
  try {
    return await httpJson<{ success: boolean; message: string }>('/api/v1/process/block-permanent', {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
  } catch (httpErr) {
    if (!isTauriRuntime()) {
      throwServiceUnavailable('/api/v1/process/block-permanent', httpErr);
    }
    return ipc<{ success: boolean; message: string }>('block_process_permanent_cmd', { name });
  }
}

export async function analyzeProcessInSandbox(
  pid: number
): Promise<{ success: boolean; message: string }> {
  try {
    return await httpJson<{ success: boolean; message: string }>('/api/v1/process/sandbox', {
      method: 'POST',
      body: JSON.stringify({ pid }),
    });
  } catch (httpErr) {
    if (!isTauriRuntime()) {
      throwServiceUnavailable('/api/v1/process/sandbox', httpErr);
    }
    return ipc<{ success: boolean; message: string }>('analyze_process_in_sandbox_cmd', { pid });
  }
}

export async function scanFileMultiEngine(
  filename: string,
  data: number[]
): Promise<MultiEngineScanResult> {
  try {
    return await httpJson<MultiEngineScanResult>('/api/v1/scan/file-multiengine', {
      method: 'POST',
      body: JSON.stringify({ filename, data }),
    });
  } catch (httpErr) {
    if (!isTauriRuntime()) {
      throwServiceUnavailable('/api/v1/scan/file-multiengine', httpErr);
    }
    return ipc<MultiEngineScanResult>('scan_file_multi_engine_cmd', { filename, data });
  }
}

export async function scanUrlMultiEngine(url: string): Promise<MultiEngineScanResult> {
  try {
    return await httpJson<MultiEngineScanResult>('/api/v1/scan/url-multiengine', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  } catch (httpErr) {
    if (!isTauriRuntime()) {
      throwServiceUnavailable('/api/v1/scan/url-multiengine', httpErr);
    }
    return ipc<MultiEngineScanResult>('scan_url_multi_engine_cmd', { url });
  }
}

export async function getPendingAlerts(): Promise<ThreatAlert[]> {
  try {
    return await httpJson<ThreatAlert[]>('/api/v1/alerts/pending');
  } catch {
    return ipc<ThreatAlert[]>('get_pending_alerts_cmd');
  }
}

export async function getLiveScanStats(): Promise<LiveScanStats> {
  try {
    const payload = await httpJson<{ type?: string; data?: LiveScanStats }>('/api/v1/live-stats');
    if (payload?.data) {
      return payload.data;
    }
  } catch {
    // Fallback to Tauri IPC below.
  }

  const payload = await ipc<{ type?: string; data?: LiveScanStats }>('get_live_scan_stats_cmd');
  return payload?.data ?? {
    files_per_sec: 0,
    events_per_sec: 0,
    total_scanned: 0,
    threats_today: 0,
    threats_total: 0,
    monitors_active: [],
    av_cpu: 0,
    av_ram_mb: 0,
    scan_progress_percent: 0,
    uptime_secs: 0,
    last_scan_file: '',
  };
}

export async function submitAlertDecision(
  alertId: string,
  action: 'block_immediately' | 'monitor_only' | 'allow_permanently'
): Promise<{ success: boolean; message: string }> {
  try {
    return await httpJson<{ success: boolean; message: string }>('/api/v1/alerts/decision', {
      method: 'POST',
      body: JSON.stringify({
        alert_id: alertId,
        action,
      }),
    });
  } catch {
    return ipc<{ success: boolean; message: string }>('submit_alert_decision_cmd', {
      alert_id: alertId,
      action,
    });
  }
}

export async function takeThreatAction(
  threatId: string,
  action: 'quarantine' | 'allow' | 'delete'
): Promise<{ success: boolean; message: string }> {
  try {
    return await httpJson<{ success: boolean; message: string }>('/api/v1/threats/action', {
      method: 'POST',
      body: JSON.stringify({
        threat_id: threatId,
        action,
      }),
    });
  } catch (httpErr) {
    if (!isTauriRuntime()) {
      throwServiceUnavailable('/api/v1/threats/action', httpErr);
    }
    return ipc<{ success: boolean; message: string }>('take_threat_action_cmd', {
      threat_id: threatId,
      action,
    });
  }
}

export async function deepInvestigate(
  target: string,
  targetType: 'network' | 'file' | 'process'
): Promise<InvestigationReport> {
  const normalize = (raw: InvestigationReportWire): InvestigationReport => {
    const fallbackAi: InvestigationAIAssessment = {
      threatClassification: 'unknown',
      malwareFamily: null,
      attackVectors: [],
      payloadType: null,
      plainEnglishSummary: 'Investigation completed but no detailed summary was returned.',
    };
    return {
      target: String(raw?.target ?? target),
      targetType: String(raw?.targetType ?? raw?.target_type ?? targetType),
      verdict: String(raw?.verdict ?? 'unknown'),
      confidence: typeof raw?.confidence === 'number' ? raw.confidence : 0,
      engineFindings: Array.isArray(raw?.engineFindings)
        ? raw.engineFindings
        : Array.isArray(raw?.engine_findings)
          ? raw.engine_findings
          : [],
      behavioralAnalysis: (raw?.behavioralAnalysis ?? raw?.behavioral_analysis ?? {
        fileOperations: [],
        networkConnections: [],
        processIndicators: [],
        persistenceIndicators: [],
      }) as InvestigationBehavioralAnalysis,
      aiAssessment: (raw?.aiAssessment ?? raw?.ai_assessment ?? fallbackAi) as InvestigationAIAssessment,
      iocs: Array.isArray(raw?.iocs) ? raw.iocs : [],
      threatFamilies: Array.isArray(raw?.threatFamilies)
        ? raw.threatFamilies
        : Array.isArray(raw?.threat_families)
          ? raw.threat_families
          : [],
      recommendations: Array.isArray(raw?.recommendations) ? raw.recommendations : [],
      timestamp: typeof raw?.timestamp === 'number' ? raw.timestamp : Date.now(),
    };
  };

  try {
    const report = await httpJson<InvestigationReportWire>('/api/v1/investigate', {
      method: 'POST',
      body: JSON.stringify({
        target,
        targetType,
      }),
    });
    return normalize(report);
  } catch (httpErr) {
    if (!isTauriRuntime()) {
      throw new Error(
        `Cannot reach av-service via HTTP (${serviceBaseUrl()}). Start av-service on port 3001 or set VITE_AV_SERVICE_URL. Details: ${String(httpErr)}`
      );
    }
    const report = await ipc<InvestigationReportWire>('deep_investigate_cmd', {
      target,
      target_type: targetType,
    });
    return normalize(report);
  }
}

export async function investigateAction(
  target: string,
  targetType: 'network' | 'file' | 'process',
  action: 'quarantine' | 'block' | 'monitor'
): Promise<{ success: boolean; message: string }> {
  try {
    return await httpJson<{ success: boolean; message: string }>('/api/v1/investigate/action', {
      method: 'POST',
      body: JSON.stringify({
        target,
        targetType,
        action,
      }),
    });
  } catch (httpErr) {
    if (!isTauriRuntime()) {
      throwServiceUnavailable('/api/v1/investigate/action', httpErr);
    }
    return ipc<{ success: boolean; message: string }>('investigate_action_cmd', {
      target,
      target_type: targetType,
      action,
    });
  }
}

export { defaultSettings, defaultStats };
