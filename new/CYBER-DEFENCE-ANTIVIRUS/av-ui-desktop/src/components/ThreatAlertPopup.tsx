import type { ThreatAlert } from '../lib/backend';

type Props = {
  alert: ThreatAlert | null;
  onAction: (action: 'block_immediately' | 'monitor_only' | 'allow_permanently') => Promise<void>;
  onOpenCyberShield?: () => void;
};

function ThreatAlertPopup({ alert, onAction, onOpenCyberShield }: Props) {
  if (!alert) return null;

  return (
    <div className="alert-overlay" role="dialog" aria-modal="true" aria-labelledby="alert-title">
      <div className={`alert-modal alert-${alert.severity.toLowerCase()}`}>
        <h2 id="alert-title">Threat Detected: {alert.threat_name}</h2>
        <p>{alert.ai_explanation}</p>
        <div className="alert-detail-grid">
          <div>
            <strong>File</strong>
            <div>{alert.file_path}</div>
          </div>
          <div>
            <strong>Process</strong>
            <div>
              {alert.process_name} {alert.pid > 0 ? `(PID ${alert.pid})` : ''}
            </div>
          </div>
          <div>
            <strong>Severity</strong>
            <div>{alert.severity}</div>
          </div>
          <div>
            <strong>Confidence</strong>
            <div>{Math.round(alert.confidence * 100)}%</div>
          </div>
        </div>
        <div className="alert-actions">
          <button className="alert-btn alert-open" onClick={() => onOpenCyberShield?.()}>
            Open Threats
          </button>
          <button className="alert-btn alert-block" onClick={() => void onAction('block_immediately')}>
            Block
          </button>
          <button className="alert-btn alert-monitor" onClick={() => void onAction('monitor_only')}>
            Monitor Only
          </button>
          <button className="alert-btn alert-allow" onClick={() => void onAction('allow_permanently')}>
            Allow
          </button>
        </div>
      </div>
    </div>
  );
}

export default ThreatAlertPopup;
