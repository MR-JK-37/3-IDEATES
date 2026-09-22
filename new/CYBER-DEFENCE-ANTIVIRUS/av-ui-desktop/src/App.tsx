import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import Dashboard from './components/Dashboard';
import LiveScanMeter from './components/LiveScanMeter';
import NetworkLogs from './components/NetworkLogs';
import ProcessLogs from './components/ProcessLogs';
import ThreatLog from './components/ThreatLog';
import ThreatAlertPopup from './components/ThreatAlertPopup';
import Settings from './components/Settings';
import VirusTotalScanner from './components/VirusTotalScanner';
import ThemeSwitcher from './components/ThemeSwitcher';
import { MobileNav, ResponsiveLayout } from './components/layouts/ResponsiveLayout';
import { useBreakpoint } from './hooks/useBreakpoint';
import {
  defaultSettings,
  defaultStats,
  getBackendHealth,
  getAppSettings,
  getLiveScanStats,
  getNetworkLogs,
  getPendingAlerts,
  getProcessLogs,
  getProtectionStatus,
  getRecentThreats,
  getSystemStats,
  saveAppSettings,
  submitAlertDecision,
  type AppSettings,
  type DashboardStats,
  type NetworkLogEntry,
  type ProcessLogEntry,
  type ProtectionStatus,
  type Threat,
  type ThreatAlert,
} from './lib/backend';
import './App.css';

type TabType = 'dashboard' | 'process' | 'network' | 'scanner' | 'threats' | 'settings';
const isTauriRuntime = '__TAURI_IPC__' in (window as unknown as Record<string, unknown>);

const tabConfig: { key: TabType; label: string; mobileIcon: string }[] = [
  { key: 'dashboard', label: 'Dashboard', mobileIcon: 'Home' },
  { key: 'process', label: 'Process', mobileIcon: 'Proc' },
  { key: 'network', label: 'Network', mobileIcon: 'Net' },
  { key: 'scanner', label: 'Scanner', mobileIcon: 'Scan' },
  { key: 'threats', label: 'Threats', mobileIcon: 'Alert' },
  { key: 'settings', label: 'Settings', mobileIcon: 'Cfg' },
];

function App() {
  const breakpoint = useBreakpoint();
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [protectionStatus, setProtectionStatus] = useState<ProtectionStatus | null>(null);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [processLogs, setProcessLogs] = useState<ProcessLogEntry[]>([]);
  const [networkLogs, setNetworkLogs] = useState<NetworkLogEntry[]>([]);
  const [stats, setStats] = useState<DashboardStats>(defaultStats);
  const [settings, setSettings] = useState<AppSettings>(defaultSettings);
  const [connected, setConnected] = useState(false);
  const [backendSource, setBackendSource] = useState<'service-http' | 'tauri-ipc' | 'offline'>('offline');
  const [healthChecked, setHealthChecked] = useState(false);
  const [pendingAlerts, setPendingAlerts] = useState<ThreatAlert[]>([]);
  const notifiedAlertIdsRef = useRef<Set<string>>(new Set());

  const refreshRuntimeData = useCallback(async () => {
    const [healthResult, statusResult, threatsResult, statsResult, liveResult, processResult, networkResult] =
      await Promise.allSettled([
        getBackendHealth(),
        getProtectionStatus(),
        getRecentThreats(),
        getSystemStats(),
        getLiveScanStats(),
        getProcessLogs(),
        getNetworkLogs(),
      ]);

    if (healthResult.status === 'fulfilled') {
      setConnected(healthResult.value.online);
      setBackendSource(healthResult.value.source);
      setHealthChecked(true);
    } else {
      setConnected(false);
      setBackendSource('offline');
      setHealthChecked(true);
    }

    if (statusResult.status === 'fulfilled') {
      setProtectionStatus(statusResult.value);
    } else if (healthResult.status === 'fulfilled' && !healthResult.value.online) {
      setProtectionStatus({ is_protected: false, last_scan: 'Backend unavailable' });
    }

    if (threatsResult.status === 'fulfilled') {
      setThreats(Array.isArray(threatsResult.value) ? threatsResult.value : []);
    }
    if (processResult.status === 'fulfilled') {
      setProcessLogs(processResult.value);
    }
    if (networkResult.status === 'fulfilled') {
      setNetworkLogs(networkResult.value);
    }

    if (statsResult.status === 'fulfilled') {
      setStats((prev) => ({ ...prev, ...statsResult.value }));
    }
    if (liveResult.status === 'fulfilled') {
      setStats((prev) => ({
        ...prev,
        cpuUsage: liveResult.value.av_cpu,
        memoryUsage: liveResult.value.av_ram_mb,
        threatsBlocked: Math.max(prev.threatsBlocked, liveResult.value.threats_total),
        lastScan: liveResult.value.last_scan_file
          ? `Scanned: ${liveResult.value.last_scan_file}`
          : prev.lastScan,
      }));
    }
  }, []);

  const loadSettings = useCallback(async () => {
    try {
      const backendSettings = await getAppSettings();
      setSettings(backendSettings);
    } catch {
      setSettings(defaultSettings);
    }
  }, []);

  const handleSaveSettings = useCallback(async (nextSettings: AppSettings) => {
    const saved = await saveAppSettings(nextSettings);
    setSettings(saved);
  }, []);

  useEffect(() => {
    void refreshRuntimeData();
    void loadSettings();
    const interval = setInterval(() => {
      void refreshRuntimeData();
    }, 1200);
    return () => clearInterval(interval);
  }, [loadSettings, refreshRuntimeData]);

  useEffect(() => {
    const timer = setInterval(() => {
      void getPendingAlerts()
        .then((alerts) => setPendingAlerts(alerts))
        .catch(() => setPendingAlerts([]));
    }, 900);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!('Notification' in window)) return;
    if (Notification.permission === 'default') {
      void Notification.requestPermission();
    }
  }, []);

  useEffect(() => {
    if (!('Notification' in window) || Notification.permission !== 'granted') {
      return;
    }

    for (const alert of pendingAlerts) {
      if (notifiedAlertIdsRef.current.has(alert.id)) continue;
      notifiedAlertIdsRef.current.add(alert.id);

      const notification = new Notification(`CyberShield: ${alert.threat_name}`, {
        body: `${alert.severity} risk detected. Click to open CyberShield Threats.`,
        tag: `cybershield-alert-${alert.id}`,
        requireInteraction: alert.severity === 'Critical' || alert.severity === 'High',
      } as NotificationOptions);

      notification.onclick = () => {
        if (isTauriRuntime) {
          void invoke('open_cybershield');
        } else {
          window.focus();
        }
        setActiveTab('threats');
        notification.close();
      };
    }
  }, [pendingAlerts]);

  useEffect(() => {
    if (!isTauriRuntime) return;

    let disposeBatch: (() => void) | null = null;
    let disposeOpen: (() => void) | null = null;

    void import('@tauri-apps/api/event')
      .then(async ({ listen }) => {
        disposeBatch = await listen<{ count: number; threats: ThreatAlert[] }>('threat_batch', (event) => {
          if (!event.payload) return;
          setPendingAlerts((prev) => [...event.payload.threats, ...prev]);
          setActiveTab('threats');
        });

        disposeOpen = await listen('open_threats_view', () => {
          setActiveTab('threats');
          void getPendingAlerts()
            .then((alerts) => setPendingAlerts(alerts))
            .catch(() => {});
        });
      })
      .catch(() => {});

    return () => {
      if (disposeBatch) disposeBatch();
      if (disposeOpen) disposeOpen();
    };
  }, []);

  const handleAlertAction = useCallback(
    async (action: 'block_immediately' | 'monitor_only' | 'allow_permanently') => {
      const alert = pendingAlerts[0];
      if (!alert) return;
      await submitAlertDecision(alert.id, action);
      setPendingAlerts((prev) => prev.filter((x) => x.id !== alert.id));
      await refreshRuntimeData();
    },
    [pendingAlerts, refreshRuntimeData]
  );

  const openCyberShield = useCallback(async () => {
    setActiveTab('threats');
    if (!isTauriRuntime) {
      window.focus();
      return;
    }

    await invoke('open_cybershield').catch(() => {});
  }, []);

  const statusLabel = useMemo(() => {
    if (!protectionStatus) return 'Syncing';
    return protectionStatus.is_protected ? 'Protected' : 'At Risk';
  }, [protectionStatus]);

  const desktopNav = breakpoint !== 'mobile';

  return (
    <ResponsiveLayout>
      <div className="app-shell">
        <div className="animated-background" aria-hidden="true">
          <div className="bg-orb bg-orb-a" />
          <div className="bg-orb bg-orb-b" />
          <div className="bg-grid" />
          <div className="bg-scan-lines" />
        </div>

        <header className="topbar animate-slide-in-bottom">
          <div className="brand-block">
            <div className="brand-mark" aria-hidden="true">CS</div>
            <div>
              <h1>CyberShield Antivirus</h1>
              <p>Enterprise endpoint defense with live telemetry and active containment</p>
            </div>
          </div>

          <div className="topbar-actions">
            <ThemeSwitcher />
            <div className={`live-chip ${connected ? 'online' : 'offline'}`}>
              <span className="live-dot" />
              <span>
                {!healthChecked
                  ? 'Checking service...'
                  : connected
                    ? backendSource === 'service-http'
                      ? 'Service Online (Real API)'
                      : 'Service Online (IPC Fallback)'
                    : 'Service Offline'}
              </span>
            </div>
          </div>
        </header>

        <section className="hero-metrics animate-slide-in-bottom">
          <article className="hero-card">
            <p className="hero-label">Protection</p>
            <h2>{statusLabel}</h2>
            <small>{protectionStatus?.last_scan ?? 'Syncing telemetry'}</small>
          </article>
          <article className="hero-card">
            <p className="hero-label">Threats Blocked</p>
            <h2>{stats.threatsBlocked}</h2>
            <small>Live count from runtime scanner</small>
          </article>
          <article className="hero-card">
            <p className="hero-label">Engine</p>
            <h2>{stats.engineVersion || 'N/A'}</h2>
            <small>
              CPU {stats.cpuUsage.toFixed(1)}% | RAM {Math.max(0, stats.memoryUsage).toFixed(0)} MB
            </small>
          </article>
        </section>

        {desktopNav && (
          <nav className="navigation" aria-label="Main navigation">
            {tabConfig.map((tab) => (
              <button
                key={tab.key}
                className={`nav-btn ${activeTab === tab.key ? 'active' : ''}`}
                onClick={() => setActiveTab(tab.key)}
              >
                {tab.label}
                {tab.key === 'threats' && <span className="count-pill">{threats.length}</span>}
              </button>
            ))}
          </nav>
        )}

        <main className="main-content animate-fade-in">
          {activeTab === 'dashboard' && (
            <>
              <LiveScanMeter />
              <Dashboard stats={stats} threats={threats} onScanComplete={refreshRuntimeData} />
            </>
          )}
          {activeTab === 'process' && <ProcessLogs logs={processLogs} />}
          {activeTab === 'network' && <NetworkLogs logs={networkLogs} />}
          {activeTab === 'scanner' && <VirusTotalScanner />}
          {activeTab === 'threats' && <ThreatLog threats={threats} />}
          {activeTab === 'settings' && <Settings settings={settings} onSave={handleSaveSettings} />}
        </main>

        {breakpoint === 'mobile' && (
          <MobileNav
            tabs={tabConfig.map((tab) => ({ key: tab.key, label: tab.label, icon: tab.mobileIcon }))}
            activeTab={activeTab}
            onSelect={(tab) => setActiveTab(tab as TabType)}
          />
        )}

        <ThreatAlertPopup
          alert={pendingAlerts[0] ?? null}
          onAction={handleAlertAction}
          onOpenCyberShield={() => void openCyberShield()}
        />

        <footer className="footer">
          <p>CyberShield v1.0.0 | Realtime protection active in background</p>
        </footer>
      </div>
    </ResponsiveLayout>
  );
}

export default App;
