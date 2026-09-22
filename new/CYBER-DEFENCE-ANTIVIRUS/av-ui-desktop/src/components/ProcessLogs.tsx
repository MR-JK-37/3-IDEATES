import React, { useMemo, useState } from 'react';
import {
  blockProcessPermanent,
  blockProcessTemp,
  killProcess,
  type ProcessLogEntry,
} from '../lib/backend';
import ProcessExplainModal from './ProcessExplainModal';
import SandboxModal from './SandboxModal';

type Props = {
  logs: ProcessLogEntry[];
};

const ProcessLogs: React.FC<Props> = ({ logs }) => {
  const [activeMenuPid, setActiveMenuPid] = useState<number | null>(null);
  const [actionResult, setActionResult] = useState<string>('');
  const [explainTarget, setExplainTarget] = useState<ProcessLogEntry | null>(null);
  const [sandboxPath, setSandboxPath] = useState<string | null>(null);

  const sorted = useMemo(
    () => [...logs].sort((a, b) => (b.suspicious ? 1 : 0) - (a.suspicious ? 1 : 0) || b.cpu_percent - a.cpu_percent),
    [logs]
  );

  const isSystemProcess = (entry: ProcessLogEntry): boolean => {
    const protectedProcesses = [
      'system',
      'csrss.exe',
      'smss.exe',
      'services.exe',
      'lsass.exe',
      'winlogon.exe',
      'svchost.exe',
      'explorer.exe',
      'systemd',
      'init',
      'kernel_task',
      'kthreadd',
      'rcu_',
    ];
    const name = entry.name.toLowerCase();
    return entry.protected || protectedProcesses.some((p) => name.includes(p));
  };

  const handleEndTask = async (entry: ProcessLogEntry) => {
    if (!window.confirm(`Terminate ${entry.name} (PID ${entry.pid})? This may cause instability.`)) {
      return;
    }
    const result = await killProcess(entry.pid);
    setActionResult(result.message);
    setActiveMenuPid(null);
  };

  const handleBlockTemp = async (entry: ProcessLogEntry) => {
    const result = await blockProcessTemp(entry.name, 3600);
    setActionResult(result.message);
    setActiveMenuPid(null);
  };

  const handleBlockPermanent = async (entry: ProcessLogEntry) => {
    if (!window.confirm(`Permanently block ${entry.name}?`)) {
      return;
    }
    const result = await blockProcessPermanent(entry.name);
    setActionResult(result.message);
    setActiveMenuPid(null);
  };

  const handleSandbox = async (entry: ProcessLogEntry) => {
    if (!entry.exe_path) {
      setActionResult('Sandbox requires an executable path for this process.');
      return;
    }
    setSandboxPath(entry.exe_path);
    setActiveMenuPid(null);
  };

  return (
    <section className="panel logs-view">
      <div className="logs-toolbar">
        <h2>Active Process Logs</h2>
        <span className="help-text">Use row actions to explain, block, sandbox, or terminate.</span>
      </div>

      {actionResult && <div className="scan-result">{actionResult}</div>}

      <div className="logs-table">
        <div className="logs-table-head">
          <span>PID</span>
          <span>Name</span>
          <span>CPU%</span>
          <span>Memory%</span>
          <span>Network</span>
          <span>Action</span>
        </div>

        <div className="logs-table-body">
          {sorted.map((entry) => (
            <div key={`${entry.pid}-${entry.name}`} className={`logs-table-row ${entry.suspicious ? 'row-risk' : ''}`}>
              <span>{entry.pid}</span>
              <span>{entry.name}</span>
              <span>{entry.cpu_percent.toFixed(1)}</span>
              <span>{entry.memory_percent.toFixed(1)}</span>
              <span>{entry.network_activity ?? '-'}</span>
              <span className="row-actions">
                <button className="mini-btn" onClick={() => setExplainTarget(entry)}>
                  Explain
                </button>
                {!isSystemProcess(entry) ? (
                  <div className="row-menu-wrap">
                    <button className="mini-btn neutral" onClick={() => setActiveMenuPid(activeMenuPid === entry.pid ? null : entry.pid)}>
                      ⋮
                    </button>
                    {activeMenuPid === entry.pid && (
                      <div className="row-menu">
                        <button onClick={() => handleEndTask(entry)} className="menu-danger">End Task</button>
                        <button onClick={() => handleBlockTemp(entry)} className="menu-warn">Block Temporarily (1h)</button>
                        <button onClick={() => handleBlockPermanent(entry)} className="menu-danger">Block Permanently</button>
                        <button onClick={() => handleSandbox(entry)}>Analyze in Sandbox</button>
                      </div>
                    )}
                  </div>
                ) : (
                  <span className="help-text">Protected</span>
                )}
              </span>
            </div>
          ))}
          {sorted.length === 0 && <div className="logs-empty">No process telemetry available.</div>}
        </div>
      </div>

      {explainTarget && <ProcessExplainModal proc={explainTarget} onClose={() => setExplainTarget(null)} />}
      {sandboxPath && <SandboxModal filePath={sandboxPath} onClose={() => setSandboxPath(null)} />}
    </section>
  );
};

export default ProcessLogs;
