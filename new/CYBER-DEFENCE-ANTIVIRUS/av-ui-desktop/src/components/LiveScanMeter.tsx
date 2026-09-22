import { useEffect, useRef, useState } from 'react';
import { getLiveScanStats, type LiveScanStats } from '../lib/backend';

function Sparkline({
  data,
  color,
  width = 120,
  height = 36,
}: {
  data: number[];
  color: string;
  width?: number;
  height?: number;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const { width, height } = canvas;

    ctx.clearRect(0, 0, width, height);
    if (data.length < 2) return;

    const max = Math.max(...data, 1);
    const step = width / (data.length - 1);

    const gradient = ctx.createLinearGradient(0, 0, 0, height);
    gradient.addColorStop(0, `${color}66`);
    gradient.addColorStop(1, `${color}00`);

    ctx.beginPath();
    ctx.moveTo(0, height - (data[0] / max) * height);
    data.forEach((value, index) => {
      ctx.lineTo(index * step, height - (value / max) * height);
    });
    ctx.lineTo(width, height);
    ctx.lineTo(0, height);
    ctx.fillStyle = gradient;
    ctx.fill();

    ctx.beginPath();
    ctx.moveTo(0, height - (data[0] / max) * height);
    data.forEach((value, index) => {
      ctx.lineTo(index * step, height - (value / max) * height);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.stroke();
  }, [data, color]);

  return <canvas ref={canvasRef} width={width} height={height} style={{ display: 'block', width: '100%', height }} />;
}

function MiniSparkCanvas({ data, color, height = 28 }: { data: number[]; color: string; height?: number }) {
  return <Sparkline data={data} color={color} height={height} width={220} />;
}

function formatUptime(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

const initialStats: LiveScanStats = {
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

function StatCard({
  label,
  value,
  unit,
  color,
  sublabel,
  miniHistory,
}: {
  label: string;
  value: number | string;
  unit: string;
  color: string;
  sublabel?: string;
  miniHistory?: number[];
}) {
  const display =
    typeof value === 'number'
      ? value >= 1000
        ? value.toLocaleString()
        : value.toFixed(value % 1 === 0 ? 0 : 1)
      : value;

  return (
    <div
      style={{
        position: 'relative',
        flex: 1,
        minHeight: 120,
        background: `linear-gradient(160deg, ${color}10 0%, ${color}04 100%)`,
        border: `1px solid ${color}22`,
        borderRadius: 12,
        padding: '16px 18px',
        overflow: 'hidden',
        minWidth: 0,
      }}
    >
      <div
        style={{
          position: 'absolute',
          top: 0,
          left: '20%',
          right: '20%',
          height: 2,
          background: `linear-gradient(90deg, transparent, ${color}cc, transparent)`,
          borderRadius: 1,
          zIndex: 10,
        }}
      />
      <div
        style={{
          position: 'relative',
          zIndex: 5,
          fontSize: 9,
          fontFamily: "'JetBrains Mono', monospace",
          fontWeight: 600,
          letterSpacing: '0.16em',
          textTransform: 'uppercase',
          color: `${color}99`,
          marginBottom: 8,
        }}
      >
        {label}
      </div>
      <div
        style={{
          position: 'relative',
          zIndex: 5,
          fontFamily: "'Syne', sans-serif",
          fontWeight: 800,
          fontSize: 36,
          lineHeight: 1,
          marginBottom: 6,
          color,
          textShadow: `0 0 20px ${color}66`,
          letterSpacing: '-0.02em',
        }}
      >
        {display}
      </div>
      <div
        style={{
          position: 'relative',
          zIndex: 5,
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11,
          color: `${color}66`,
          marginBottom: sublabel ? 5 : 0,
          letterSpacing: '0.05em',
        }}
      >
        {unit}
      </div>
      {sublabel && (
        <div
          style={{
            position: 'relative',
            zIndex: 5,
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 10,
            color: 'rgba(255,255,255,0.22)',
            letterSpacing: '0.03em',
          }}
        >
          {sublabel}
        </div>
      )}
      {miniHistory && miniHistory.length > 1 && (
        <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, height: 40, zIndex: 1, opacity: 0.18, pointerEvents: 'none' }}>
          <MiniSparkCanvas data={miniHistory} color={color} height={40} />
        </div>
      )}
    </div>
  );
}

export default function LiveScanMeter() {
  const [stats, setStats] = useState<LiveScanStats>(initialStats);
  const [scanHistory, setScanHistory] = useState<number[]>(Array(30).fill(0));
  const [eventHistory, setEventHistory] = useState<number[]>(Array(30).fill(0));
  const [cpuHistory, setCpuHistory] = useState<number[]>(Array(30).fill(0));
  const [threatHistory, setThreatHistory] = useState<number[]>(Array(30).fill(0));

  useEffect(() => {
    let active = true;

    const tick = async () => {
      try {
        const next = await getLiveScanStats();
        if (!active) return;
        setStats(next);
        setScanHistory((prev) => [...prev.slice(1), next.files_per_sec]);
        setEventHistory((prev) => [...prev.slice(1), next.events_per_sec]);
        setCpuHistory((prev) => [...prev.slice(1), next.av_cpu]);
        setThreatHistory((prev) => [...prev.slice(1), next.threats_today]);
      } catch {
        // Keep last known telemetry to avoid flickering to zero on transient transport failures.
        if (active) setStats((prev) => prev);
      }
    };

    void tick();
    const interval = setInterval(() => void tick(), 1000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="glass-card live-meter">
      <div className="live-meter-head">
        <div>
          <div className="live-title">LIVE SCAN ACTIVITY</div>
          <div className="live-subtitle">Uptime: {formatUptime(stats.uptime_secs)}</div>
        </div>
        <div className="status-protected">ACTIVE</div>
      </div>

      <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
        <StatCard label="TOTAL SCANNED" value={stats.total_scanned} unit="files" color="#00d4ff" miniHistory={scanHistory} />
        <StatCard label="SCAN RATE" value={stats.files_per_sec} unit="files/sec" color="#7b2fff" miniHistory={scanHistory} />
        <StatCard label="KERNEL EVENTS" value={stats.events_per_sec} unit="events/sec" color="#7b2fff" miniHistory={eventHistory} />
        <StatCard
          label="THREATS TODAY"
          value={stats.threats_today}
          unit="detected today"
          color={stats.threats_today > 0 ? '#ff3366' : '#00ff88'}
          sublabel={`${stats.threats_total} total blocked`}
          miniHistory={threatHistory}
        />
      </div>

      <div className="progress-wrap">
        <div className="progress-head">
          <span>SYSTEM SCAN COVERAGE</span>
          <span>{stats.scan_progress_percent.toFixed(1)}%</span>
        </div>
        <div className="progress-track">
          <div className="progress-fill" style={{ width: `${stats.scan_progress_percent}%` }} />
        </div>
      </div>

      <div className="monitor-row">
        {stats.monitors_active.map((monitor) => (
          <span key={monitor.name} className={`monitor-pill ${monitor.active ? 'on' : 'off'}`}>
            {monitor.name} {monitor.events_count > 0 ? `(${monitor.events_count})` : ''}
          </span>
        ))}
      </div>

      {stats.last_scan_file && (
        <div className="last-file" title={stats.last_scan_file}>
          ▶ {stats.last_scan_file}
        </div>
      )}

      <div
        style={{
          display: 'flex',
          gap: 20,
          padding: '10px 14px',
          background: 'rgba(0,0,0,0.25)',
          borderRadius: 8,
          marginTop: 10,
          alignItems: 'center',
          flexWrap: 'wrap',
        }}
      >
        {[
          { label: 'AV CPU', value: `${stats.av_cpu.toFixed(1)}%`, color: stats.av_cpu > 15 ? '#ffaa00' : '#00ff88' },
          { label: 'AV RAM', value: `${stats.av_ram_mb}MB`, color: '#00d4ff' },
          { label: 'UPTIME', value: formatUptime(stats.uptime_secs), color: 'rgba(255,255,255,0.5)' },
        ].map((item) => (
          <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)', letterSpacing: '0.1em' }}>{item.label}</span>
            <span style={{ fontFamily: "'JetBrains Mono'", fontSize: 12, fontWeight: 600, color: item.color }}>
              {item.value}
            </span>
          </div>
        ))}
        <div style={{ flex: 1, height: 24, opacity: 0.6 }}>
          <MiniSparkCanvas data={cpuHistory} color="#ffaa00" height={24} />
        </div>
      </div>
    </div>
  );
}
