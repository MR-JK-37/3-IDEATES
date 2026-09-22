import React, { useState } from 'react';
import {
  scanFileMultiEngine,
  scanUrlMultiEngine,
  type MultiEngineScanResult,
} from '../lib/backend';
import SandboxModal from './SandboxModal';

const VirusTotalScanner: React.FC = () => {
  const [scanType, setScanType] = useState<'url' | 'file'>('file');
  const [input, setInput] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<MultiEngineScanResult | null>(null);
  const [error, setError] = useState('');
  const [sandboxTarget, setSandboxTarget] = useState('');
  const [openSandboxPath, setOpenSandboxPath] = useState<string | null>(null);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) {
      setFile(droppedFile);
      setError('');
    }
  };

  const handleScan = async () => {
    setScanning(true);
    setError('');
    setResults(null);

    try {
      if (scanType === 'file' && file) {
        const fileData = await file.arrayBuffer();
        const data = Array.from(new Uint8Array(fileData));
        const result = await scanFileMultiEngine(file.name, data);
        setResults(result);
      } else if (scanType === 'url' && input.trim()) {
        const result = await scanUrlMultiEngine(input.trim());
        setResults(result);
      }
    } catch (scanError) {
      setError(`Scan failed: ${String(scanError)}`);
    } finally {
      setScanning(false);
    }
  };

  return (
    <section className="panel logs-view">
      <div className="logs-toolbar">
        <h2>Advanced Multi-Engine Scanner</h2>
      </div>

      <div className="scan-mode-row">
        <button className={`nav-btn ${scanType === 'file' ? 'active' : ''}`} onClick={() => setScanType('file')}>
          File Scan
        </button>
        <button className={`nav-btn ${scanType === 'url' ? 'active' : ''}`} onClick={() => setScanType('url')}>
          URL Scan
        </button>
      </div>

      {scanType === 'file' && (
        <div className="drop-zone" onDrop={handleDrop} onDragOver={(e) => e.preventDefault()}>
          {file ? (
            <div>
              <div>{file.name}</div>
              <small>{(file.size / 1024 / 1024).toFixed(2)} MB</small>
              <div>
                <button className="btn-reset" onClick={() => setFile(null)}>
                  Remove
                </button>
              </div>
            </div>
          ) : (
            <div>
              <div>Drag and drop file here</div>
              <small>or</small>
              <div>
                <input
                  type="file"
                  onChange={(e) => setFile(e.target.files?.[0] || null)}
                />
              </div>
            </div>
          )}
        </div>
      )}

      {scanType === 'url' && (
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="https://example.com"
          className="scan-path-input"
        />
      )}

      <button
        onClick={handleScan}
        disabled={scanning || (scanType === 'file' && !file) || (scanType === 'url' && !input.trim())}
        className="btn-scan"
      >
        {scanning ? 'Scanning...' : 'Scan Now'}
      </button>

      {error && <div className="scan-result">{error}</div>}

      {results && (
        <div className="scan-results">
          <div className={`scan-summary ${results.malicious > 0 ? 'row-risk' : ''}`}>
            {results.malicious > 0 ? 'MALICIOUS' : 'CLEAN'}: {results.malicious} / {results.total} engines
          </div>
          <div className="engine-grid">
            {results.engines.map((engine) => (
              <div key={engine.name} className={`engine-card ${engine.detected ? 'row-risk' : ''}`}>
                <strong>{engine.name}</strong>
                <div>{engine.detected ? engine.result : 'Clean'}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="scan-quick" style={{ marginTop: 16 }}>
        <h3 style={{ marginBottom: 8 }}>Sandbox Analysis</h3>
        <p className="section-subtitle">
          Run a local file path in isolated behavioral analysis (strace-based).
        </p>
        <div className="scan-input-row">
          <input
            type="text"
            value={sandboxTarget}
            onChange={(e) => setSandboxTarget(e.target.value)}
            className="scan-path-input"
            placeholder="/absolute/path/to/file"
          />
          <button
            className="btn-scan"
            disabled={!sandboxTarget.trim()}
            onClick={() => setOpenSandboxPath(sandboxTarget.trim())}
          >
            Analyze in Sandbox
          </button>
        </div>
      </div>

      {openSandboxPath && (
        <SandboxModal
          filePath={openSandboxPath}
          onClose={() => setOpenSandboxPath(null)}
        />
      )}
    </section>
  );
};

export default VirusTotalScanner;
