import { useEffect, useMemo, useState } from 'react';
import {
  deepInvestigate,
  investigateAction,
  type InvestigationReport,
} from '../lib/backend';

type Props = {
  target: string;
  targetType: 'network' | 'file' | 'process';
  onClose: () => void;
};

function verdictColor(verdict: string): string {
  switch (verdict) {
    case 'clean':
      return '#00ff88';
    case 'suspicious':
      return '#ffaa00';
    case 'malicious':
      return '#ff6600';
    case 'highly_malicious':
      return '#ff3366';
    default:
      return '#00d4ff';
  }
}

export default function InvestigationModal({ target, targetType, onClose }: Props) {
  const [report, setReport] = useState<InvestigationReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState('');
  const [actionResult, setActionResult] = useState<string>('');
  const [refreshTick, setRefreshTick] = useState(0);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setActionResult('');
    setErrorMessage('');
    void deepInvestigate(target, targetType)
      .then((res) => {
        if (active) setReport(res);
      })
      .catch((e) => {
        if (!active) return;
        setReport(null);
        setErrorMessage(`Investigation failed: ${String(e)}`);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [target, targetType, refreshTick]);

  const color = useMemo(() => verdictColor(report?.verdict ?? 'clean'), [report?.verdict]);

  const handleAction = async (action: 'quarantine' | 'block' | 'monitor') => {
    try {
      const result = await investigateAction(target, targetType, action);
      setActionResult(result.message);
    } catch (e) {
      setActionResult(`Action failed: ${String(e)}`);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        background: 'rgba(2,6,16,0.82)',
        backdropFilter: 'blur(10px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 16,
        animation: 'fadeInBackdrop 220ms ease both',
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: 760,
          maxHeight: '92vh',
          overflowY: 'auto',
          borderRadius: 16,
          background: 'linear-gradient(165deg, var(--panel), var(--bg-surface))',
          border: '1px solid var(--border)',
          boxShadow: '0 24px 60px rgba(0, 0, 0, 0.38)',
          animation: 'slideUpScale 260ms ease both',
        }}
      >
        <div
          style={{
            padding: '16px 18px',
            borderBottom: '1px solid rgba(255,255,255,0.08)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 8,
          }}
        >
          <div>
            <div style={{ fontFamily: "'Syne', sans-serif", fontWeight: 800, fontSize: 20 }}>
              🔍 Deep Investigation Report
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-soft)', marginTop: 3 }}>
              {targetType.toUpperCase()} · {target}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              padding: '8px 12px',
              borderRadius: 9,
              border: '1px solid rgba(255,255,255,0.18)',
              background: 'rgba(255,255,255,0.06)',
              color: 'var(--text)',
              cursor: 'pointer',
            }}
          >
            Close
          </button>
        </div>

        {loading && (
          <div style={{ padding: 24, textAlign: 'center', color: 'rgba(255,255,255,0.8)' }}>
            Deep investigation in progress...
          </div>
        )}

        {!loading && report && (
          <div style={{ padding: 18, display: 'grid', gap: 14 }}>
            <div
              style={{
                borderRadius: 12,
                border: `1px solid ${color}50`,
                background: `${color}14`,
                padding: '14px 16px',
              }}
            >
              <div style={{ fontWeight: 800, color, fontSize: 16, marginBottom: 6 }}>
                {report.verdict.replace('_', ' ').toUpperCase()} · {(report.confidence * 100).toFixed(0)}%
              </div>
              <div style={{ fontSize: 13, lineHeight: 1.8, color: 'rgba(255,255,255,0.86)' }}>
                {report.aiAssessment?.plainEnglishSummary ?? 'No detailed summary available.'}
              </div>
            </div>

            {Array.isArray(report.engineFindings) && report.engineFindings.length > 0 && (
              <div style={{ border: '1px solid rgba(255,255,255,0.12)', borderRadius: 12, padding: 14 }}>
                <div style={{ fontWeight: 700, marginBottom: 8, color: '#ff8855' }}>🎯 Engine Findings</div>
                <div style={{ display: 'grid', gap: 8 }}>
                  {report.engineFindings.map((f, i) => (
                    <div key={`${f.name}-${i}`} style={{ fontSize: 12, color: 'rgba(255,255,255,0.82)' }}>
                      <strong>{f.name}</strong> [{f.severity}] · {f.description}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {Array.isArray(report.iocs) && report.iocs.length > 0 && (
              <div style={{ border: '1px solid rgba(255,255,255,0.12)', borderRadius: 12, padding: 14 }}>
                <div style={{ fontWeight: 700, marginBottom: 8, color: '#ffaa00' }}>🚨 Indicators of Compromise</div>
                <div style={{ display: 'grid', gap: 6 }}>
                  {report.iocs.map((ioc, i) => (
                    <div key={`${ioc.iocType}-${ioc.value}-${i}`} style={{ fontSize: 12, color: 'rgba(255,255,255,0.82)' }}>
                      <strong>{ioc.iocType}</strong>: {ioc.value} ({ioc.reputation})
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div style={{ border: '1px solid rgba(255,255,255,0.12)', borderRadius: 12, padding: 14 }}>
              <div style={{ fontWeight: 700, marginBottom: 8, color: '#00ff88' }}>✅ Recommended Actions</div>
              <div style={{ display: 'grid', gap: 6 }}>
                {(Array.isArray(report.recommendations) ? report.recommendations : []).map((r, i) => (
                  <div key={`${r}-${i}`} style={{ fontSize: 13, color: 'rgba(255,255,255,0.86)' }}>
                    • {r}
                  </div>
                ))}
                {(!Array.isArray(report.recommendations) || report.recommendations.length === 0) && (
                  <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.72)' }}>
                    • Monitor this target and run a full scan if behavior changes.
                  </div>
                )}
              </div>
            </div>

            {actionResult && (
              <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.78)' }}>{actionResult}</div>
            )}

            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {targetType === 'file' && (
                <button
                  onClick={() => void handleAction('quarantine')}
                  style={{
                    padding: '10px 14px',
                    borderRadius: 9,
                    border: '1px solid rgba(255,51,102,0.40)',
                    background: 'rgba(255,51,102,0.18)',
                    color: '#ff8ba8',
                    cursor: 'pointer',
                    fontWeight: 700,
                  }}
                >
                  🚫 Quarantine
                </button>
              )}
              {targetType === 'process' && (
                <button
                  onClick={() => void handleAction('block')}
                  style={{
                    padding: '10px 14px',
                    borderRadius: 9,
                    border: '1px solid rgba(255,170,0,0.40)',
                    background: 'rgba(255,170,0,0.18)',
                    color: '#ffca66',
                    cursor: 'pointer',
                    fontWeight: 700,
                  }}
                >
                  🔒 Block
                </button>
              )}
              <button
                onClick={() => void handleAction('monitor')}
                style={{
                  padding: '10px 14px',
                  borderRadius: 9,
                  border: '1px solid rgba(0,212,255,0.40)',
                  background: 'rgba(0,212,255,0.15)',
                  color: '#7fe9ff',
                  cursor: 'pointer',
                  fontWeight: 700,
                }}
              >
                👁 Monitor
              </button>
            </div>
          </div>
        )}

        {!loading && !report && (
          <div style={{ padding: 24, display: 'grid', gap: 12 }}>
            <div style={{ color: '#ff8ba8', fontWeight: 800, fontSize: 17 }}>
              Unable to generate investigation report
            </div>
            <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.78)' }}>
              {errorMessage || 'No report payload was returned from backend.'}
            </div>
            <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.56)' }}>
              Target: {targetType} · {target}
            </div>
            <div style={{ display: 'flex', gap: 8, marginTop: 2 }}>
              <button
                onClick={() => setRefreshTick((v) => v + 1)}
                style={{
                  padding: '9px 13px',
                  borderRadius: 10,
                  border: '1px solid var(--border)',
                  background: 'rgba(69,214,255,0.12)',
                  color: 'var(--accent)',
                  cursor: 'pointer',
                  fontWeight: 700,
                }}
              >
                Retry
              </button>
              <button
                onClick={onClose}
                style={{
                  padding: '9px 13px',
                  borderRadius: 10,
                  border: '1px solid rgba(255,255,255,0.2)',
                  background: 'rgba(255,255,255,0.08)',
                  color: 'var(--text)',
                  cursor: 'pointer',
                  fontWeight: 700,
                }}
              >
                Dismiss
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
