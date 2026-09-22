import React, { useMemo, useState } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { Threat } from '../lib/backend';
import { runDeepSearch, runScan } from '../lib/backend';
import InvestigationModal from './InvestigationModal';
import ThreatDistributionChart from './charts/ThreatDistributionChart';

interface DashboardProps {
  stats: {
    threatsBlocked: number;
    lastScan: string;
    engineVersion: string;
    cpuUsage: number;
    memoryUsage: number;
  };
  threats: Threat[];
  onScanComplete?: () => void;
}

type ThreatKind = 'network' | 'file' | 'process';

type ActivityItem = {
  id: string;
  name: string;
  kind: ThreatKind;
  details: string;
  severity: string;
  timestamp: string;
  count: number;
};

function inferThreatKind(threat: Threat): ThreatKind {
  const src = `${threat.path} ${threat.name} ${threat.engine ?? ''}`.toLowerCase();
  if (src.includes('network') || src.includes('tcp') || src.includes('udp') || src.includes('ip:')) return 'network';
  if (src.includes('process') || src.includes('pid') || src.includes('.exe')) return 'process';
  return 'file';
}

function normalizeSeverity(threat: Threat): string {
  const raw = (threat.severity || '').toLowerCase();
  const name = (threat.name || '').toLowerCase();
  if (raw.includes('critical') || name.includes('ransom') || name.includes('trojan')) return 'critical';
  if (raw.includes('high') || name.includes('backdoor')) return 'high';
  if (raw.includes('medium') || name.includes('suspicious')) return 'medium';
  return 'low';
}

function formatRelativeTime(iso: string): string {
  const ts = new Date(iso).getTime();
  if (Number.isNaN(ts)) return '--';
  const diffMs = Date.now() - ts;
  if (diffMs < 60_000) return 'Just now';
  const mins = Math.floor(diffMs / 60_000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function dayKey(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function chartLabel(date: Date, isToday: boolean): string {
  if (isToday) return 'Today';
  return `${date.toLocaleDateString('en-US', { month: 'short' })} ${date.getDate()}`;
}

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ borderRadius: 10, border: '1px solid var(--border)', background: 'var(--bg-surface)', padding: '8px 10px' }}>
      <div style={{ fontSize: 11, color: 'var(--text-soft)', marginBottom: 4 }}>{label}</div>
      {payload.map((p: any) => (
        <div key={p.dataKey} style={{ display: 'flex', justifyContent: 'space-between', gap: 12, fontSize: 12 }}>
          <span style={{ color: 'var(--text-soft)' }}>{p.name}</span>
          <strong style={{ color: 'var(--accent)' }}>{p.value}</strong>
        </div>
      ))}
    </div>
  );
}

const cardStyle: React.CSSProperties = {
  background: 'var(--panel)',
  borderRadius: 16,
  border: '1px solid var(--border)',
  padding: 18,
  backdropFilter: 'blur(14px)',
  animation: 'cs-fadein 420ms ease both',
};

const Dashboard: React.FC<DashboardProps> = ({ stats, threats, onScanComplete }) => {
  const [scanPath, setScanPath] = useState('');
  const [scanning, setScanning] = useState(false);
  const [deepScanning, setDeepScanning] = useState(false);
  const [scanResult, setScanResult] = useState<string | null>(null);
  const [investigateTarget, setInvestigateTarget] = useState<{ target: string; targetType: ThreatKind } | null>(null);

  const timeline = useMemo(() => {
    const today = new Date();
    const counts: Record<string, number> = {};
    for (const t of threats) {
      const ts = new Date(t.timestamp);
      if (Number.isNaN(ts.getTime())) continue;
      const key = dayKey(ts);
      counts[key] = (counts[key] || 0) + 1;
    }

    return Array.from({ length: 7 }, (_, idx) => {
      const d = new Date(today);
      d.setDate(today.getDate() - (6 - idx));
      const key = dayKey(d);
      return {
        day: chartLabel(d, idx === 6),
        threats: counts[key] || 0,
      };
    });
  }, [threats]);

  const groupedActivity = useMemo(() => {
    const map = new Map<string, ActivityItem>();
    for (const t of threats) {
      const kind = inferThreatKind(t);
      const severity = normalizeSeverity(t);
      const details = t.path || 'Unknown source';
      const name = (t.name || 'Unknown Threat').split('(')[0].trim();
      const key = `${kind}|${name}|${details}`;
      const current = map.get(key);
      if (!current) {
        map.set(key, {
          id: key,
          name,
          kind,
          details,
          severity,
          timestamp: t.timestamp,
          count: 1,
        });
      } else {
        current.count += 1;
        if (new Date(t.timestamp).getTime() > new Date(current.timestamp).getTime()) {
          current.timestamp = t.timestamp;
        }
      }
    }
    return [...map.values()]
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, 10);
  }, [threats]);

  const threatTypes = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const t of threats) {
      const name = (t.name || 'Unknown').replace(/\(\d+(\.\d+)?\)\s*$/u, '').trim() || 'Unknown';
      counts[name] = (counts[name] || 0) + 1;
    }
    return Object.entries(counts).map(([name, count]) => ({ name, count }));
  }, [threats]);

  const criticalCount = threats.filter((t) => normalizeSeverity(t) === 'critical').length;
  const highCount = threats.filter((t) => normalizeSeverity(t) === 'high').length;
  const protectedStatus = criticalCount + highCount === 0;

  const handleScan = async () => {
    if (!scanPath.trim()) return;
    setScanning(true);
    setScanResult(null);
    try {
      const root = scanPath.trim();
      const deep = await runDeepSearch(root, 3000);
      const result = await runScan(root);
      setScanResult(`Deep Search queued ${deep.queued_files} files from ${deep.root_path}. Then ${result.verdict}.`);
      onScanComplete?.();
    } catch (error) {
      setScanResult(`Scan error: ${String(error)}`);
    } finally {
      setScanning(false);
    }
  };

  const handleDeepSearch = async () => {
    setDeepScanning(true);
    setScanResult(null);
    try {
      const result = await runDeepSearch(scanPath.trim() || undefined, 3000);
      setScanResult(`Deep Search queued ${result.queued_files} files from ${result.root_path}.`);
      onScanComplete?.();
    } catch (error) {
      setScanResult(`Deep Search error: ${String(error)}`);
    } finally {
      setDeepScanning(false);
    }
  };

  return (
    <div style={{ minHeight: '100%', borderRadius: 18, background: 'linear-gradient(145deg, var(--bg-surface), var(--bg-1))', border: '1px solid var(--border)', padding: 20, animation: 'cs-slideup 500ms ease both' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 18 }}>
        <div>
          <h2 style={{ fontFamily: "'Syne', sans-serif", fontWeight: 800, fontSize: 28, lineHeight: 1, marginBottom: 6 }}>CyberShield Dashboard</h2>
          <p style={{ color: 'var(--text-soft)', fontSize: 12 }}>Live endpoint telemetry from backend runtime</p>
        </div>
        <div style={{ borderRadius: 999, padding: '8px 14px', border: '1px solid var(--panel-border)', color: protectedStatus ? 'var(--ok)' : 'var(--danger)', background: 'rgba(255,255,255,0.06)', fontWeight: 700, fontSize: 12 }}>
          {protectedStatus ? 'PROTECTED' : 'AT RISK'}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(220px,1fr))', gap: 12, marginBottom: 16 }}>
        <div style={{ ...cardStyle, animationDelay: '0ms' }}><small style={{ color: 'var(--text-soft)' }}>Threats Blocked</small><div className="stat-number">{stats.threatsBlocked}</div></div>
        <div style={{ ...cardStyle, animationDelay: '70ms' }}><small style={{ color: 'var(--text-soft)' }}>Engine</small><div className="stat-number">{stats.engineVersion || 'N/A'}</div></div>
        <div style={{ ...cardStyle, animationDelay: '140ms' }}><small style={{ color: 'var(--text-soft)' }}>CPU</small><div className="stat-number">{stats.cpuUsage.toFixed(1)}%</div></div>
        <div style={{ ...cardStyle, animationDelay: '210ms' }}><small style={{ color: 'var(--text-soft)' }}>RAM</small><div className="stat-number">{Math.max(0, stats.memoryUsage).toFixed(0)} MB</div></div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(320px,1fr))', gap: 14, marginBottom: 14 }}>
        <div style={cardStyle}>
          <h3 style={{ marginBottom: 10 }}>Threat Timeline</h3>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={timeline}>
              <defs>
                <linearGradient id="threatArea" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--accent)" stopOpacity={0.45} />
                  <stop offset="100%" stopColor="var(--accent)" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="4 4" stroke="rgba(179,210,245,0.15)" />
              <XAxis dataKey="day" stroke="var(--text-soft)" tickLine={false} axisLine={false} />
              <YAxis stroke="var(--text-soft)" allowDecimals={false} />
              <Tooltip content={<ChartTooltip />} />
              <Area type="monotone" dataKey="threats" name="Threats" stroke="var(--accent)" fill="url(#threatArea)" strokeWidth={2} />
              <Line type="monotone" dataKey="threats" stroke="var(--ok)" strokeWidth={2} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div style={cardStyle}>
          <h3 style={{ marginBottom: 10 }}>Threat Distribution</h3>
          <ThreatDistributionChart data={threatTypes} />
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(320px,1fr))', gap: 14 }}>
        <div style={{ ...cardStyle, padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '16px 16px 8px' }}>
            <h3 style={{ marginBottom: 4 }}>Recent Activity</h3>
            <p style={{ color: 'var(--text-soft)', fontSize: 12 }}>Latest grouped detections</p>
          </div>
          <div style={{ maxHeight: 320, overflowY: 'auto' }}>
            {groupedActivity.length === 0 && <div style={{ padding: 16, color: 'var(--text-soft)' }}>No threats detected.</div>}
            {groupedActivity.map((item) => (
              <div key={item.id} style={{ padding: '12px 16px', borderTop: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'space-between', gap: 10 }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontWeight: 700, fontSize: 13 }}>{item.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-soft)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{item.kind}: {item.details}</div>
                </div>
                <div style={{ display: 'grid', justifyItems: 'end', gap: 6 }}>
                  <span style={{ fontSize: 11, color: 'var(--text-soft)' }}>{formatRelativeTime(item.timestamp)}</span>
                  <button className="nav-btn" onClick={() => setInvestigateTarget({ target: item.details, targetType: item.kind })}>Investigate</button>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div style={cardStyle}>
          <h3 style={{ marginBottom: 8 }}>Quick Scan</h3>
          <input
            type="text"
            className="scan-path-input"
            placeholder="/path/to/file or directory"
            value={scanPath}
            onChange={(e) => setScanPath(e.target.value)}
          />
          <div style={{ display: 'grid', gap: 10, marginTop: 10 }}>
            <button className="btn-scan" onClick={handleScan} disabled={scanning || !scanPath.trim()}>{scanning ? 'Scanning...' : 'Deep Search + Scan'}</button>
            <button className="nav-btn" onClick={handleDeepSearch} disabled={deepScanning}>{deepScanning ? 'Deep Searching...' : 'Deep Search Only'}</button>
          </div>
          {scanResult && <div className="scan-result" style={{ marginTop: 10 }}>{scanResult}</div>}
          <div style={{ marginTop: 12, paddingTop: 10, borderTop: '1px solid rgba(255,255,255,0.08)', color: 'var(--text-soft)', fontSize: 11 }}>
            <div>Engine: {stats.engineVersion || 'N/A'}</div>
            <div>Last Scan: {stats.lastScan || 'Awaiting telemetry'}</div>
          </div>
        </div>
      </div>

      {investigateTarget && (
        <InvestigationModal
          target={investigateTarget.target}
          targetType={investigateTarget.targetType}
          onClose={() => setInvestigateTarget(null)}
        />
      )}
    </div>
  );
};

export default Dashboard;
