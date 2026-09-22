import React, { useMemo, useState } from 'react';
import { explainThreat, takeThreatAction, type Threat } from '../lib/backend';

interface ThreatLogProps {
  threats: Threat[];
}

const ThreatLog: React.FC<ThreatLogProps> = ({ threats }) => {
  const [selectedThreat, setSelectedThreat] = useState<string | null>(null);
  const [filter, setFilter] = useState<'All' | 'Critical' | 'High' | 'Medium' | 'Low'>('All');
  const [loadingExplainId, setLoadingExplainId] = useState<string | null>(null);
  const [loadingActionId, setLoadingActionId] = useState<string | null>(null);
  const [aiExplanations, setAiExplanations] = useState<Record<string, string>>({});
  const [actionResults, setActionResults] = useState<Record<string, string>>({});

  const scoreFromName = (name: string): number => {
    const m = name.match(/\(([\d.]+)\)/);
    if (!m) return 0;
    const n = parseFloat(m[1]);
    if (Number.isNaN(n)) return 0;
    return n <= 1 ? n * 100 : n;
  };

  const isLikelyFalsePositive = (threat: Threat): boolean => {
    const lowerPath = threat.path.toLowerCase();
    const ext = lowerPath.split('.').pop() ?? '';
    const nonExec = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg', 'md', 'txt', 'rst'];
    if (!nonExec.includes(ext)) return false;
    return threat.name.toLowerCase().includes('ml.');
  };

  const formatTimeAgo = (iso: string): string => {
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return iso;
    const diffMs = Date.now() - t;
    if (diffMs < 60_000) return 'Just now';
    const mins = Math.floor(diffMs / 60_000);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return '#dc2626';
      case 'High':
        return '#ea580c';
      case 'Medium':
        return '#eab308';
      case 'Low':
        return '#22c55e';
      default:
        return '#888';
    }
  };

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'Blocked':
        return '🚫';
      case 'Quarantined':
        return '🔒';
      case 'Allowed':
        return '✅';
      default:
        return '❓';
    }
  };

  const filteredThreats = useMemo(
    () =>
      threats.filter((threat) => {
        if (filter === 'All') return true;
        return threat.severity === filter;
      }),
    [filter, threats]
  );

  const handleAction = async (threat: Threat, action: 'quarantine' | 'allow' | 'delete') => {
    setLoadingActionId(threat.id);
    try {
      const result = await takeThreatAction(threat.id, action);
      setActionResults((prev) => ({
        ...prev,
        [threat.id]:
          action === 'quarantine'
            ? 'Quarantined'
            : action === 'allow'
              ? 'Allowed'
              : 'Deleted',
      }));
      setAiExplanations((prev) => ({
        ...prev,
        [threat.id]: `${prev[threat.id] ? `${prev[threat.id]}\n\n` : ''}${result.message}`,
      }));
    } catch (error) {
      setAiExplanations((prev) => ({
        ...prev,
        [threat.id]: `Action failed: ${String(error)}`,
      }));
    } finally {
      setLoadingActionId(null);
    }
  };

  const handleExplain = async (threat: Threat) => {
    if (loadingExplainId) return;
    setLoadingExplainId(threat.id);
    try {
      const explanation = await explainThreat({
        id: threat.id,
        name: threat.name,
        path: threat.path,
        severity: threat.severity,
        engine: threat.engine ?? 'CyberShield Engine',
        action: threat.action,
      });
      setAiExplanations((prev) => ({ ...prev, [threat.id]: explanation }));
    } catch (error) {
      console.error('Threat explanation failed:', error);
      setAiExplanations((prev) => ({
        ...prev,
        [threat.id]: 'Could not generate analysis right now. Try again shortly.',
      }));
    } finally {
      setLoadingExplainId(null);
    }
  };

  return (
    <div className="threat-log">
      <div className="log-header">
        <h1>Threat History</h1>
        <div className="filter-controls">
          <button
            className={`filter-btn ${filter === 'All' ? 'active' : ''}`}
            onClick={() => setFilter('All')}
          >
            All ({threats.length})
          </button>
          <button
            className={`filter-btn ${filter === 'Critical' ? 'active' : ''}`}
            onClick={() => setFilter('Critical')}
          >
            Critical
          </button>
          <button
            className={`filter-btn ${filter === 'High' ? 'active' : ''}`}
            onClick={() => setFilter('High')}
          >
            High
          </button>
          <button
            className={`filter-btn ${filter === 'Medium' ? 'active' : ''}`}
            onClick={() => setFilter('Medium')}
          >
            Medium
          </button>
          <button
            className={`filter-btn ${filter === 'Low' ? 'active' : ''}`}
            onClick={() => setFilter('Low')}
          >
            Low
          </button>
        </div>
      </div>

      <div className="threats-table">
        <div className="table-header">
          <div className="col-threat">Threat Name</div>
          <div className="col-path">File Path</div>
          <div className="col-severity">Severity</div>
          <div className="col-action">Action Taken</div>
          <div className="col-time">Timestamp</div>
        </div>

        <div className="table-body">
          {filteredThreats.length > 0 ? (
            filteredThreats.map((threat) => (
              <div
                key={threat.id}
                className={`table-row ${selectedThreat === threat.id ? 'selected' : ''}`}
                onClick={() => setSelectedThreat(selectedThreat === threat.id ? null : threat.id)}
              >
                <div className="col-threat">{threat.name}</div>
                <div className="col-path" title={threat.path}>
                  {threat.path.split('/').pop() || threat.path}
                </div>
                <div className="col-severity">
                  <span
                    className="severity-badge"
                    style={{ color: isLikelyFalsePositive(threat) ? '#ffaa00' : getSeverityColor(threat.severity) }}
                  >
                    {isLikelyFalsePositive(threat) ? 'Review' : threat.severity}
                  </span>
                </div>
                <div className="col-action">
                  <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                    <button
                      className="mini-btn"
                      onClick={(event) => {
                        event.stopPropagation();
                        void handleAction(threat, 'quarantine');
                      }}
                      disabled={loadingActionId === threat.id}
                    >
                      🚫 Quarantine
                    </button>
                    <button
                      className="mini-btn neutral"
                      onClick={(event) => {
                        event.stopPropagation();
                        void handleAction(threat, 'allow');
                      }}
                      disabled={loadingActionId === threat.id}
                    >
                      ✅ Allow
                    </button>
                    <span className="action-icon">{getActionIcon(actionResults[threat.id] ?? threat.action)}</span>
                    <span>{actionResults[threat.id] ?? threat.action}</span>
                  </div>
                </div>
                <div className="col-time">{formatTimeAgo(threat.timestamp)}</div>

                {selectedThreat === threat.id && (
                  <div className="threat-details">
                    <div className="details-header">
                      <h3>Threat Details</h3>
                      <button className="close-btn" onClick={() => setSelectedThreat(null)}>
                        ✕
                      </button>
                    </div>
                    <div className="details-content">
                      <div className="detail-item">
                        <span className="label">Name:</span>
                        <span className="value">{threat.name}</span>
                      </div>
                      <div className="detail-item">
                        <span className="label">Path:</span>
                        <span className="value">{threat.path}</span>
                      </div>
                      <div className="detail-item">
                        <span className="label">Severity:</span>
                        <span
                          className="value"
                          style={{ color: getSeverityColor(threat.severity) }}
                        >
                          {threat.severity}
                        </span>
                      </div>
                      <div className="detail-item">
                        <span className="label">Action:</span>
                        <span className="value">{threat.action}</span>
                      </div>
                      <div className="detail-item">
                        <span className="label">Engine:</span>
                        <span className="value">{threat.engine || 'Unknown'}</span>
                      </div>
                      <div className="detail-item">
                        <span className="label">Time:</span>
                        <span className="value">{formatTimeAgo(threat.timestamp)}</span>
                      </div>
                      <div className="detail-item">
                        <span className="label">Confidence:</span>
                        <span className="value">{scoreFromName(threat.name).toFixed(0)}%</span>
                      </div>
                      {isLikelyFalsePositive(threat) && (
                        <div className="detail-item">
                          <span className="label">Review:</span>
                          <span className="value">Likely false positive for non-executable file type.</span>
                        </div>
                      )}
                      {threat.details && (
                        <div className="detail-item">
                          <span className="label">Details:</span>
                          <span className="value">{threat.details}</span>
                        </div>
                      )}
                      <div className="detail-item">
                        <button
                          className="mini-btn"
                          onClick={(event) => {
                            event.stopPropagation();
                            void handleExplain(threat);
                          }}
                          disabled={loadingExplainId === threat.id}
                        >
                          {loadingExplainId === threat.id ? 'Analyzing...' : 'Explain'}
                        </button>
                      </div>
                      {aiExplanations[threat.id] && (
                        <div className="detail-item">
                          <span className="label">AI Impact:</span>
                          <span className="value">{aiExplanations[threat.id]}</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ))
          ) : (
            <div className="no-results">
              <p>No threats found matching the selected filter.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ThreatLog;
