import { useEffect, useState } from 'react';
import { deepExplainConnection, type NetExplainDeepResult, type NetworkLogEntry } from '../lib/backend';

type Props = {
  conn: NetworkLogEntry;
  onClose: () => void;
};

function formatBytes(b: number) {
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1048576).toFixed(2)} MB`;
}

function ExplainSection({
  icon,
  title,
  color,
  text,
  delay = 0,
}: {
  icon: string;
  title: string;
  color: string;
  text: string;
  delay?: number;
}) {
  return (
    <div
      style={{
        background: `linear-gradient(135deg, ${color}09 0%, ${color}03 100%)`,
        border: `1px solid ${color}22`,
        borderRadius: 14,
        padding: '20px 22px',
        animation: `slideInFromRight 0.4s cubic-bezier(0.34, 1.56, 0.64, 1) ${delay}s backwards`,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <span style={{ fontSize: 20, lineHeight: 1 }}>{icon}</span>
        <span
          style={{
            fontWeight: 700,
            fontSize: 13,
            color,
            fontFamily: "'JetBrains Mono', monospace",
            letterSpacing: '0.02em',
          }}
        >
          {title}
        </span>
      </div>
      <div
        style={{
          fontSize: 14,
          color: 'rgba(255,255,255,0.80)',
          lineHeight: 2.0,
          fontFamily: "'JetBrains Mono', monospace",
        }}
      >
        {text}
      </div>
    </div>
  );
}

export default function NetworkExplainModal({ conn, onClose }: Props) {
  const [result, setResult] = useState<NetExplainDeepResult | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    void deepExplainConnection({
      protocol: conn.protocol,
      local_address: conn.local_address,
      remote_address: conn.remote_address,
      state: conn.state,
      process: conn.process,
      pid: conn.pid,
      bytes_sent: conn.bytes_sent,
      bytes_received: conn.bytes_received,
    })
      .then((res) => {
        if (active) setResult(res);
      })
      .catch((error) => {
        if (!active) return;
        setResult({
          verdict: 'SUSPICIOUS',
          risk_color: '#ffaa00',
          packet_label: `${conn.process ?? 'Unknown'} -> ${conn.remote_address} via ${conn.protocol.toUpperCase()}`,
          plain_english: `Unable to deeply analyze this connection. ${String(error)}`,
          what_data_moving: `Outgoing ${formatBytes(conn.bytes_sent ?? 0)} / Incoming ${formatBytes(conn.bytes_received ?? 0)}.`,
          where_going: `Destination ${conn.remote_address}.`,
          safety_reason: 'Manual review is recommended.',
          user_action: 'Monitor this connection. Block if destination is untrusted.',
        });
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [conn]);

  const severityColor =
    result?.verdict === 'SAFE' ? '#00ff88' : result?.verdict === 'SUSPICIOUS' ? '#ffaa00' : '#ff3366';

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.90)',
        backdropFilter: 'blur(12px)',
        zIndex: 9999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px',
        animation: 'fadeInBackdrop 0.2s ease',
      }}
    >
      <div
        style={{
          background: 'linear-gradient(135deg, rgba(4,10,24,0.98) 0%, rgba(8,18,38,0.98) 100%)',
          border: `1px solid ${severityColor}28`,
          borderRadius: 18,
          width: '100%',
          maxWidth: 720,
          maxHeight: '92vh',
          overflowY: 'auto',
          boxShadow: `0 0 80px ${severityColor}18, 0 40px 120px rgba(0,0,0,0.95)`,
          animation: 'slideUpScale 0.35s cubic-bezier(0.34, 1.56, 0.64, 1)',
        }}
      >
        <div
          style={{
            padding: '26px 30px',
            borderBottom: '1px solid rgba(255,255,255,0.06)',
            background: 'rgba(0,0,0,0.3)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div
                style={{
                  fontFamily: "'Syne', sans-serif",
                  fontWeight: 800,
                  fontSize: 22,
                  marginBottom: 8,
                  letterSpacing: '-0.01em',
                }}
              >
                🔍 Network Connection Analysis
              </div>
              <div
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 11,
                  color: 'rgba(255,255,255,0.45)',
                  letterSpacing: '0.02em',
                }}
              >
                {conn.protocol?.toUpperCase()} · {conn.local_address} → {conn.remote_address}
              </div>
            </div>
            <button
              onClick={onClose}
              style={{
                background: 'rgba(255,255,255,0.07)',
                border: '1px solid rgba(255,255,255,0.14)',
                color: 'rgba(255,255,255,0.6)',
                borderRadius: 10,
                padding: '10px 18px',
                cursor: 'pointer',
                fontSize: 12,
                fontFamily: "'JetBrains Mono', monospace",
                fontWeight: 600,
                transition: 'all 0.2s',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = 'rgba(255,255,255,0.12)';
                e.currentTarget.style.color = '#fff';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = 'rgba(255,255,255,0.07)';
                e.currentTarget.style.color = 'rgba(255,255,255,0.6)';
              }}
            >
              ✕ Close
            </button>
          </div>
        </div>

        <div
          style={{
            padding: '32px 34px',
            display: 'grid',
            gridTemplateRows: 'auto',
            rowGap: '28px',
          }}
        >
          {loading && (
            <div style={{ textAlign: 'center', padding: '44px 20px' }}>
              <div style={{ fontSize: 40, marginBottom: 14 }}>🔬</div>
              <div style={{ fontFamily: "'Syne',sans-serif", fontWeight: 700, fontSize: 15, color: '#00d4ff', marginBottom: 6 }}>
                Analyzing this connection...
              </div>
              <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.35)' }}>
                Checking IP reputation · Inspecting service type · Analyzing data flow...
              </div>
            </div>
          )}

          {result && !loading && (
            <>
              <div
                style={{
                  background: `linear-gradient(135deg, ${severityColor}0f 0%, ${severityColor}05 100%)`,
                  border: `1.5px solid ${severityColor}38`,
                  borderRadius: 14,
                  padding: '22px 24px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: 18,
                  animation: 'slideInFromRight 0.4s cubic-bezier(0.34, 1.56, 0.64, 1) 0.1s backwards',
                }}
              >
                <div
                  style={{
                    fontSize: 48,
                    lineHeight: 1,
                    flexShrink: 0,
                    animation: 'bounceIn 0.6s cubic-bezier(0.68, -0.55, 0.265, 1.55) 0.2s backwards',
                  }}
                >
                  {result.verdict === 'SAFE' ? '✅' : result.verdict === 'SUSPICIOUS' ? '⚠️' : '🚨'}
                </div>
                <div style={{ flex: 1 }}>
                  <div
                    style={{
                      fontFamily: "'Syne', sans-serif",
                      fontWeight: 800,
                      fontSize: 20,
                      color: severityColor,
                      marginBottom: 10,
                      lineHeight: 1.3,
                      letterSpacing: '-0.01em',
                    }}
                  >
                    {result.verdict}
                  </div>
                  <div
                    style={{
                      fontSize: 14,
                      color: 'rgba(255,255,255,0.85)',
                      lineHeight: 2.0,
                      fontFamily: "'JetBrains Mono', monospace",
                      fontWeight: 400,
                    }}
                  >
                    {result.plain_english}
                  </div>
                </div>
              </div>

              <ExplainSection
                icon="📊"
                title="What data is moving?"
                color="#7b2fff"
                text={result.what_data_moving}
                delay={0.15}
              />

              <ExplainSection
                icon="🗺️"
                title="Where is this data going?"
                color="#ffaa00"
                text={result.where_going}
                delay={0.2}
              />

              <ExplainSection
                icon={result.verdict === 'SAFE' ? '🛡️' : '⚠️'}
                title="Why is it safe / dangerous?"
                color={severityColor}
                text={result.safety_reason}
                delay={0.25}
              />

              <div
                style={{
                  background: 'linear-gradient(135deg, rgba(0,255,136,0.08) 0%, rgba(0,255,136,0.03) 100%)',
                  border: '1px solid rgba(0,255,136,0.25)',
                  borderRadius: 14,
                  padding: '20px 22px',
                  marginTop: 8,
                  animation: 'slideInFromRight 0.4s cubic-bezier(0.34, 1.56, 0.64, 1) 0.3s backwards',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
                  <span style={{ fontSize: 20, lineHeight: 1 }}>✅</span>
                  <span
                    style={{
                      fontWeight: 700,
                      fontSize: 13,
                      color: '#00ff88',
                      fontFamily: "'JetBrains Mono', monospace",
                      letterSpacing: '0.02em',
                    }}
                  >
                    What should you do?
                  </span>
                </div>
                <div
                  style={{
                    fontSize: 14,
                    color: 'rgba(255,255,255,0.82)',
                    lineHeight: 2.0,
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  {result.user_action}
                </div>
              </div>

              {result.verdict !== 'SAFE' && (
                <div style={{ display: 'flex', gap: 12, paddingTop: 4, animation: 'fadeInUp 0.4s ease 0.35s backwards' }}>
                  <button
                    style={{
                      flex: 1,
                      padding: '14px 0',
                      borderRadius: 11,
                      border: 'none',
                      cursor: 'pointer',
                      background: 'linear-gradient(135deg, #ff3366, #cc0033)',
                      color: '#fff',
                      fontWeight: 800,
                      fontSize: 14,
                      fontFamily: "'JetBrains Mono', monospace",
                      transition: 'all 0.25s cubic-bezier(0.4, 0, 0.2, 1)',
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.transform = 'translateY(-2px)';
                      e.currentTarget.style.boxShadow = '0 8px 24px rgba(255,51,102,0.35)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.transform = 'translateY(0)';
                      e.currentTarget.style.boxShadow = 'none';
                    }}
                  >
                    🚫 Block Connection
                  </button>
                  <button
                    style={{
                      flex: 1,
                      padding: '14px 0',
                      borderRadius: 11,
                      cursor: 'pointer',
                      background: 'rgba(255,170,0,0.12)',
                      border: '1.5px solid rgba(255,170,0,0.4)',
                      color: '#ffaa00',
                      fontWeight: 700,
                      fontSize: 14,
                      fontFamily: "'JetBrains Mono', monospace",
                      transition: 'all 0.25s cubic-bezier(0.4, 0, 0.2, 1)',
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.transform = 'translateY(-2px)';
                      e.currentTarget.style.background = 'rgba(255,170,0,0.18)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.transform = 'translateY(0)';
                      e.currentTarget.style.background = 'rgba(255,170,0,0.12)';
                    }}
                  >
                    👁 Monitor
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
