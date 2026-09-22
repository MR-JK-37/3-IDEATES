import React, { useEffect, useState } from 'react';
import {
  getAutostartStatus,
  getRealtimeProtectionStatus,
  toggleAutostart,
  toggleRealtimeProtection,
  type AppSettings,
} from '../lib/backend';

interface SettingsProps {
  settings: AppSettings;
  onSave: (settings: AppSettings) => Promise<void>;
}

const Settings: React.FC<SettingsProps> = ({ settings, onSave }) => {
  const [draft, setDraft] = useState<AppSettings>(settings);
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showConfirmDialog, setShowConfirmDialog] = useState(false);
  const [pendingRealtimeState, setPendingRealtimeState] = useState<boolean | null>(null);
  const [autostartEnabled, setAutostartEnabled] = useState(false);
  const [loadingAutostart, setLoadingAutostart] = useState(false);

  useEffect(() => {
    setDraft(settings);
  }, [settings]);

  useEffect(() => {
    let mounted = true;
    void getAutostartStatus()
      .then((status) => {
        if (mounted) setAutostartEnabled(Boolean(status.enabled));
      })
      .catch(() => {});
    void getRealtimeProtectionStatus()
      .then((status) => {
        if (!mounted) return;
        setDraft((prev) => ({ ...prev, realTimeProtection: Boolean(status.enabled) }));
      })
      .catch(() => {});
    return () => {
      mounted = false;
    };
  }, []);

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>
  ) => {
    const { name, type, value } = e.target;
    const checked = (e.target as HTMLInputElement).checked;

    setDraft((prev) => ({
      ...prev,
      [name]:
        type === 'checkbox'
          ? checked
          : type === 'number'
            ? Number.parseInt(value, 10) || 0
            : value,
    }));
  };

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      await onSave(draft);
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } catch (saveError) {
      setError(`Save failed: ${String(saveError)}`);
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    setDraft(settings);
    setError(null);
  };

  const requestRealtimeToggle = (enabled: boolean) => {
    setPendingRealtimeState(enabled);
    setShowConfirmDialog(true);
  };

  const confirmRealtimeToggle = async () => {
    if (pendingRealtimeState === null) {
      return;
    }

    setSaving(true);
    setError(null);
    try {
      await toggleRealtimeProtection(pendingRealtimeState);
      const next = { ...draft, realTimeProtection: pendingRealtimeState };
      await onSave(next);
      setDraft(next);
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } catch (saveError) {
      setError(`Toggle failed: ${String(saveError)}`);
    } finally {
      setSaving(false);
      setShowConfirmDialog(false);
      setPendingRealtimeState(null);
    }
  };

  const handleAutostartToggle = async () => {
    setLoadingAutostart(true);
    setError(null);
    try {
      const next = !autostartEnabled;
      const response = await toggleAutostart(next);
      setAutostartEnabled(Boolean(response.enabled));
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } catch (saveError) {
      setError(`Autostart update failed: ${String(saveError)}`);
    } finally {
      setLoadingAutostart(false);
    }
  };

  return (
    <div className="settings">
      <div className="settings-header">
        <h1>Security Policy Settings</h1>
        {saved && <div className="save-notification">Settings saved to backend successfully.</div>}
        {error && <div className="save-notification error">{error}</div>}
      </div>

      <div className="settings-content">
        <div className="settings-section panel">
          <h2>Real-Time Protection</h2>
          <div className="setting-item">
            <div className="setting-inline">
              <div>
                <strong>Real-Time Protection</strong>
                <p className="help-text">Continuously monitor your system for threats</p>
              </div>
              <button
                onClick={() => requestRealtimeToggle(!draft.realTimeProtection)}
                disabled={saving}
                className={`toggle-switch ${draft.realTimeProtection ? 'on' : 'off'}`}
                aria-label="Toggle real-time protection"
              >
                <span className="toggle-knob" />
              </button>
            </div>
            {!draft.realTimeProtection && (
              <p className="help-text">
                Warning: real-time protection is disabled. Historical logs remain visible, but new threats are not actively scanned.
              </p>
            )}
          </div>

          <div className="setting-item">
            <label className="checkbox-label">
              <input
                type="checkbox"
                name="realTimeProtection"
                checked={draft.realTimeProtection}
                onChange={handleChange}
              />
              <span>Enable Real-Time File Monitoring</span>
            </label>
            <p className="help-text">Continuously monitors files and processes for threats</p>
          </div>

          <div className="setting-item">
            <label className="checkbox-label">
              <input
                type="checkbox"
                name="autoScan"
                checked={draft.autoScan}
                onChange={handleChange}
              />
              <span>Enable Automatic Scanning</span>
            </label>
            <p className="help-text">Automatically scan system at specified intervals</p>
          </div>

          {draft.autoScan && (
            <div className="setting-item">
              <label htmlFor="scanInterval">Scan Interval (hours)</label>
              <input
                id="scanInterval"
                type="number"
                name="scanInterval"
                min="1"
                max="168"
                value={draft.scanInterval}
                onChange={handleChange}
                className="input-field"
              />
            </div>
          )}
        </div>

        <div className="settings-section panel">
          <h2>Startup Behavior</h2>
          <div className="setting-item">
            <div className="setting-inline">
              <div>
                <strong>Auto-start on System Boot</strong>
                <p className="help-text">Launches CyberShield in background tray mode after login.</p>
              </div>
              <button
                onClick={handleAutostartToggle}
                disabled={loadingAutostart}
                className={`toggle-switch ${autostartEnabled ? 'on' : 'off'}`}
                aria-label="Toggle startup autostart"
              >
                <span className="toggle-knob" />
              </button>
            </div>
          </div>
        </div>

        <div className="settings-section panel">
          <h2>Threat Response</h2>
          <div className="setting-item">
            <label htmlFor="threatActions">Default Action for Detected Threats</label>
            <select
              id="threatActions"
              name="threatActions"
              value={draft.threatActions}
              onChange={handleChange}
              className="select-field"
            >
              <option value="block">Block and Remove</option>
              <option value="quarantine">Quarantine</option>
              <option value="alert">Alert Only</option>
            </select>
          </div>

          <div className="setting-item">
            <label className="checkbox-label">
              <input
                type="checkbox"
                name="quarantineEnabled"
                checked={draft.quarantineEnabled}
                onChange={handleChange}
              />
              <span>Enable Quarantine Folder</span>
            </label>
            <p className="help-text">Isolate suspicious files instead of immediate deletion</p>
          </div>
        </div>

        <div className="settings-section panel">
          <h2>Notifications and Reporting</h2>
          <div className="setting-item">
            <label className="checkbox-label">
              <input
                type="checkbox"
                name="notificationsEnabled"
                checked={draft.notificationsEnabled}
                onChange={handleChange}
              />
              <span>Enable Desktop Notifications</span>
            </label>
            <p className="help-text">Receive alerts when threats are detected</p>
          </div>

          <div className="setting-item">
            <label className="checkbox-label">
              <input
                type="checkbox"
                name="reportingEnabled"
                checked={draft.reportingEnabled}
                onChange={handleChange}
              />
              <span>Send Threat Reports</span>
            </label>
            <p className="help-text">Help improve security by sharing threat data (anonymous)</p>
          </div>
        </div>

        <div className="settings-section panel">
          <h2>Advanced</h2>
          <div className="setting-item">
            <label htmlFor="excludePaths">Excluded Paths (comma-separated)</label>
            <textarea
              id="excludePaths"
              name="excludePaths"
              value={draft.excludePaths}
              onChange={handleChange}
              className="textarea-field"
              placeholder="/System,/Library"
              rows={3}
            />
            <p className="help-text">Paths that will not be scanned for threats</p>
          </div>

          <div className="setting-item">
            <label className="checkbox-label">
              <input
                type="checkbox"
                name="autoUpload"
                checked={draft.autoUpload}
                onChange={handleChange}
              />
              <span>Auto-Upload Suspicious Files for Analysis</span>
            </label>
            <p className="help-text">Send samples to AI engine for threat analysis</p>
          </div>
        </div>

        <div className="settings-actions">
          <button className="btn-save" onClick={handleSave} disabled={saving}>
            {saving ? 'Saving...' : 'Save Settings'}
          </button>
          <button className="btn-reset" onClick={handleReset} disabled={saving}>
            Reset Changes
          </button>
        </div>
      </div>

      {showConfirmDialog && (
        <div className="modal-overlay">
          <div className="modal-card">
            <h3>{pendingRealtimeState ? 'Enable' : 'Disable'} Real-Time Protection?</h3>
            {pendingRealtimeState ? (
              <p>This will resume live monitoring and scanning.</p>
            ) : (
              <p>
                Disabling real-time protection leaves the system vulnerable. Historical logs stay visible, but new threats will not be detected until re-enabled.
              </p>
            )}
            <div className="settings-actions">
              <button className="btn-save" onClick={confirmRealtimeToggle} disabled={saving}>
                Confirm
              </button>
              <button className="btn-reset" onClick={() => setShowConfirmDialog(false)} disabled={saving}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Settings;
