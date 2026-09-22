import { useEffect, useState } from 'react';
import {
  blockProcessTemp,
  deepExplainProcess,
  type ProcessExplainDeepResult,
  type ProcessLogEntry,
} from '../lib/backend';

type Props = {
  proc: ProcessLogEntry;
  onClose: () => void;
};

function ExplainSection({
  icon,
  title,
  color,
  text,
}: {
  icon: string;
  title: string;
  color: string;
  text: string;
}) {
  return (
    <div style={{ background: `${color}09`, border: `1px solid ${color}22`, borderRadius: 12, padding: '14px 16px' }}>
      <div style={{ fontWeight: 700, fontSize: 12, color, marginBottom: 7, display: 'flex', alignItems: 'center', gap: 6 }}>
        {icon} {title}
      </div>
      <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.78)', lineHeight: 1.78 }}>{text}</div>
    </div>
  );
}

export default function ProcessExplainModal({ proc, onClose }: Props) {
  const [result, setResult] = useState<ProcessExplainDeepResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [actionInfo, setActionInfo] = useState('');

  useEffect(() => {
    let active = true;
    void deepExplainProcess({
      pid: proc.pid,
      name: proc.name,
      cpu_percent: proc.cpu_percent,
      memory_percent: proc.memory_percent,
      memory_mb: proc.memory_mb,
      network_kbs: proc.network_kbs,
      exe_path: proc.exe_path ?? '',
      parent_pid: proc.parent_pid ?? 0,
    })
      .then((res) => {
        if (!active) return;
        setResult(res);
      })
      .catch((error) => {
        if (!active) return;
        setResult({
          verdict: 'SUSPICIOUS',
          risk_score: 55,
          risk_color: '#ffaa00',
          one_liner: `Unable to fully analyze ${proc.name}.`,
          what_is_this: `${proc.name} is currently active on your device.`,
          what_doing_now: `It is using ${proc.cpu_percent.toFixed(1)}% CPU and ${proc.memory_percent.toFixed(1)}% memory right now.`,
          safety_reason: `Analysis failed: ${String(error)}`,
          user_action: 'Monitor this process and block temporarily if you do not trust it.',
        });
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [proc]);

  const handleBlock = async () => {
    setBusy(true);
    try {
      const res = await blockProcessTemp(proc.name, 3600);
      setActionInfo(res.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.88)',
        backdropFilter: 'blur(10px)',
        WebkitBackdropFilter: 'blur(10px)',
        zIndex: 9999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        animation: 'cs-fadein 0.2s ease',
      }}
    >
      <div
        style={{
          background: 'rgba(6, 14, 30, 0.98)',
          border: '1px solid rgba(0,212,255,0.22)',
          borderRadius: 18,
          padding: '28px 30px',
          width: '92%',
          maxWidth: 600,
          maxHeight: '88vh',
          overflowY: 'auto',
          boxShadow: '0 0 80px rgba(0,212,255,0.12), 0 40px 100px rgba(0,0,0,0.9)',
          animation: 'cs-slideup 0.25s cubic-bezier(0.34,1.56,0.64,1)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
          <div>
            <div style={{ fontFamily: "'Syne',sans-serif", fontWeight: 800, fontSize: 20, marginBottom: 4 }}>🤖 AI Process Analysis</div>
            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 12, color: '#00d4ff' }}>
              {proc.name} · PID {proc.pid}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'rgba(255,255,255,0.07)',
              border: '1px solid rgba(255,255,255,0.12)',
              color: 'rgba(255,255,255,0.6)',
              borderRadius: 10,
              padding: '8px 16px',
              cursor: 'pointer',
              fontSize: 12,
              fontFamily: "'JetBrains Mono',monospace",
            }}
          >
            ✕ Close
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8, marginBottom: 22 }}>
          {[
            { l: 'CPU', v: `${proc.cpu_percent.toFixed(1)}%`, c: proc.cpu_percent > 70 ? '#ff3366' : proc.cpu_percent > 30 ? '#ffaa00' : '#00ff88' },
            { l: 'Memory', v: `${(proc.memory_mb ?? 0).toFixed(0)} MB`, c: '#00d4ff' },
            { l: 'Network', v: (proc.network_kbs ?? 0) > 0 ? `${proc.network_kbs} KB/s` : 'None', c: (proc.network_kbs ?? 0) > 0 ? '#00d4ff' : 'rgba(255,255,255,0.3)' },
          ].map((s) => (
            <div key={s.l} style={{ background: 'rgba(0,0,0,0.35)', borderRadius: 10, padding: '12px 14px', textAlign: 'center' }}>
              <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.35)', letterSpacing: '0.12em', marginBottom: 5 }}>{s.l}</div>
              <div style={{ fontFamily: "'Syne',sans-serif", fontWeight: 800, fontSize: 22, color: s.c }}>{s.v}</div>
            </div>
          ))}
        </div>

        {loading && (
          <div style={{ textAlign: 'center', padding: '44px 20px' }}>
            <div style={{ fontSize: 40, marginBottom: 14, animation: 'cs-pulse 1.5s infinite' }}>🔍</div>
            <div style={{ fontFamily: "'Syne',sans-serif", fontWeight: 700, fontSize: 16, color: '#00d4ff', marginBottom: 6 }}>
              Deeply analyzing {proc.name}...
            </div>
            <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.35)' }}>Checking process identity, behavior patterns, network activity...</div>
          </div>
        )}

        {result && !loading && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div
              style={{
                background: `${result.risk_color}12`,
                border: `1.5px solid ${result.risk_color}40`,
                borderRadius: 12,
                padding: '16px 18px',
                display: 'flex',
                alignItems: 'center',
                gap: 16,
              }}
            >
              <div
                style={{
                  width: 60,
                  height: 60,
                  borderRadius: '50%',
                  flexShrink: 0,
                  background: `conic-gradient(${result.risk_color} ${result.risk_score * 3.6}deg, rgba(255,255,255,0.05) 0)`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <div
                  style={{
                    width: 44,
                    height: 44,
                    borderRadius: '50%',
                    background: 'rgba(6,14,30,0.95)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontFamily: "'Syne',sans-serif",
                    fontWeight: 800,
                    fontSize: 14,
                    color: result.risk_color,
                  }}
                >
                  {result.risk_score}
                </div>
              </div>
              <div>
                <div style={{ fontFamily: "'Syne',sans-serif", fontWeight: 800, fontSize: 18, color: result.risk_color, marginBottom: 4 }}>
                  {result.verdict} {result.verdict === 'SAFE' ? '✅' : result.verdict === 'SUSPICIOUS' ? '⚠️' : '🚨'}
                </div>
                <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.75)', lineHeight: 1.6 }}>{result.one_liner}</div>
              </div>
            </div>

            <ExplainSection icon="📌" title="What is this program?" color="#00d4ff" text={result.what_is_this} />
            <ExplainSection icon="⚡" title="What is it doing right now?" color="#7b2fff" text={result.what_doing_now} />
            <ExplainSection icon={result.verdict === 'SAFE' ? '🛡️' : '⚠️'} title="Is it safe?" color={result.risk_color} text={result.safety_reason} />
            <ExplainSection icon="✅" title="What should you do?" color="#00ff88" text={result.user_action} />

            {actionInfo && <div className="scan-result">{actionInfo}</div>}
            <div style={{ display: 'flex', gap: 8, paddingTop: 4 }}>
              <button
                disabled={busy}
                onClick={() => void handleBlock()}
                style={{
                  flex: 1,
                  padding: '11px 0',
                  borderRadius: 9,
                  cursor: 'pointer',
                  background: 'rgba(255,51,102,0.12)',
                  border: '1px solid rgba(255,51,102,0.35)',
                  color: '#ff3366',
                  fontWeight: 700,
                  fontSize: 12,
                }}
              >
                🚫 Block Process
              </button>
              <button onClick={onClose} style={{ flex: 1, padding: '11px 0', borderRadius: 9, cursor: 'pointer', background: 'rgba(255,170,0,0.12)', border: '1px solid rgba(255,170,0,0.35)', color: '#ffaa00', fontWeight: 700, fontSize: 12 }}>
                👁 Monitor Only
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
