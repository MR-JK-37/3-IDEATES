import React, { useMemo, useState } from 'react';
import { type NetworkLogEntry } from '../lib/backend';
import NetworkExplainModal from './NetworkExplainModal';

type Props = {
  logs: NetworkLogEntry[];
};

const NetworkLogs: React.FC<Props> = ({ logs }) => {
  const [explainTarget, setExplainTarget] = useState<NetworkLogEntry | null>(null);

  const sorted = useMemo(
    () => [...logs].sort((a, b) => (b.suspicious ? 1 : 0) - (a.suspicious ? 1 : 0)),
    [logs]
  );

  return (
    <section className="panel logs-view">
      <div className="logs-toolbar">
        <h2>Active Network Logs</h2>
        <span className="help-text">Use Explain on each connection row.</span>
      </div>

      <div className="logs-table">
        <div className="logs-table-head network">
          <span>Protocol</span>
          <span>Local</span>
          <span>Remote</span>
          <span>State</span>
          <span>Process</span>
          <span>Action</span>
        </div>

        <div className="logs-table-body">
          {sorted.map((entry, idx) => {
            return (
              <div
                key={`${entry.local_address}-${entry.remote_address}-${idx}`}
                className={`logs-table-row network ${entry.suspicious ? 'row-risk' : ''}`}
              >
                <span>{entry.protocol}</span>
                <span>{entry.local_address}</span>
                <span>{entry.remote_address}</span>
                <span>{entry.state}</span>
                <span>{entry.process ?? '-'}</span>
                <span>
                  <button className="mini-btn" onClick={() => setExplainTarget(entry)}>
                    Explain
                  </button>
                </span>
              </div>
            );
          })}
          {sorted.length === 0 && <div className="logs-empty">No network telemetry available.</div>}
        </div>
      </div>
      {explainTarget && <NetworkExplainModal conn={explainTarget} onClose={() => setExplainTarget(null)} />}
    </section>
  );
};

export default NetworkLogs;
