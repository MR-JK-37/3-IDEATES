import { useEffect, useState } from 'react';
import { runSandbox, type SandboxReport } from '../lib/backend';

type Props = {
  filePath: string;
  onClose: () => void;
};

export default function SandboxModal({ filePath, onClose }: Props) {
  const [report, setReport] = useState<SandboxReport | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    void runSandbox(filePath)
      .then((r) => {
        if (active) setReport(r);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [filePath]);

  const verdictColor = !report
    ? '#7b2fff'
    : report.verdict === 'CLEAN'
      ? '#00ff88'
      : report.verdict === 'MALICIOUS'
        ? '#ff3366'
        : '#ffaa00';

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.90)', backdropFilter: 'blur(10px)', zIndex: 9999, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: 'rgba(5,10,25,0.98)', border: `1px solid ${verdictColor}35`, borderRadius: 18, padding: '28px 30px', width: '92%', maxWidth: 660, maxHeight: '88vh', overflowY: 'auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
          <div>
            <div style={{ fontFamily: "'Syne',sans-serif", fontWeight: 800, fontSize: 20, marginBottom: 4 }}>🧪 Sandbox Analysis</div>
            <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)', fontFamily: "'JetBrains Mono',monospace" }}>{filePath}</div>
          </div>
          <button onClick={onClose} style={{ background: 'rgba(255,255,255,0.07)', border: '1px solid rgba(255,255,255,0.12)', color: 'rgba(255,255,255,0.6)', borderRadius: 10, padding: '8px 16px', cursor: 'pointer', fontSize: 12 }}>✕</button>
        </div>

        {loading && (
          <div style={{ textAlign: 'center', padding: '60px 20px' }}>
            <div style={{ fontSize: 48, marginBottom: 16, animation: 'cs-pulse 1.5s infinite' }}>🔬</div>
            <div style={{ fontFamily: "'Syne',sans-serif", fontWeight: 700, fontSize: 18, color: '#7b2fff', marginBottom: 8 }}>Running in Virtual Environment...</div>
            <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.4)', lineHeight: 1.7 }}>
              The file is being executed in an isolated sandbox.
              <br />
              All actions are monitored - nothing can escape to your real system.
            </div>
            <div style={{ marginTop: 20, height: 3, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden' }}>
              <div style={{ height: '100%', background: 'linear-gradient(90deg,#7b2fff,#00d4ff)', animation: 'cs-scanprogress 2s ease-in-out infinite', width: '60%' }} />
            </div>
          </div>
        )}

        {report && !loading && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ background: `${verdictColor}0e`, border: `1.5px solid ${verdictColor}40`, borderRadius: 13, padding: '18px 20px', display: 'flex', alignItems: 'center', gap: 16 }}>
              <div style={{ fontSize: 52 }}>{report.verdict === 'CLEAN' ? '✅' : report.verdict === 'MALICIOUS' ? '🚨' : '⚠️'}</div>
              <div>
                <div style={{ fontFamily: "'Syne',sans-serif", fontWeight: 800, fontSize: 22, color: verdictColor, marginBottom: 5 }}>
                  {report.verdict} - {report.risk_score}/100 Risk
                </div>
                <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.8)', lineHeight: 1.7 }}>{report.ai_summary}</div>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8 }}>
              {[
                { l: 'Events', v: report.events.length, c: '#00d4ff' },
                { l: 'Files', v: report.files_accessed.length, c: '#ffaa00' },
                { l: 'Network', v: report.network_attempts.length, c: report.network_attempts.length > 0 ? '#ff3366' : '#00ff88' },
              ].map((s) => (
                <div key={s.l} style={{ background: 'rgba(0,0,0,0.35)', borderRadius: 9, padding: '12px', textAlign: 'center' }}>
                  <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.35)', letterSpacing: '0.1em', marginBottom: 4 }}>{s.l}</div>
                  <div style={{ fontFamily: "'Syne',sans-serif", fontWeight: 800, fontSize: 24, color: s.c }}>{s.v}</div>
                </div>
              ))}
            </div>

            {report.events.length > 0 && (
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'rgba(255,255,255,0.6)', marginBottom: 8 }}>📋 Behavior Timeline</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                  {report.events.slice(0, 12).map((e, i) => (
                    <div key={`${e.time}-${i}`} style={{ display: 'flex', gap: 10, padding: '8px 12px', background: 'rgba(0,0,0,0.3)', borderRadius: 8, borderLeft: `3px solid ${e.severity === 'HIGH' ? '#ff3366' : e.severity === 'MEDIUM' ? '#ffaa00' : 'rgba(255,255,255,0.12)'}` }}>
                      <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'rgba(255,255,255,0.25)', flexShrink: 0 }}>{e.time.toFixed(1)}s</span>
                      <span style={{ fontSize: 10, color: e.severity === 'HIGH' ? '#ff6688' : e.severity === 'MEDIUM' ? '#ffcc44' : 'rgba(255,255,255,0.4)', fontWeight: 600, flexShrink: 0 }}>{e.action}</span>
                      <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.65)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.detail}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
