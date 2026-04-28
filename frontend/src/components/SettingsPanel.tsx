import { Database, RefreshCw, Settings, Wifi, WifiOff } from "lucide-react";
import { useEffect, useState } from "react";

import {
  getSettings,
  getSourceStatus,
  loadSource,
  testSourceConnection,
  updateSettings
} from "../api/client";
import type {
  ApplicationSettings,
  ConnectionTestResult,
  HealthResponse,
  PrimarySourceName,
  SourceLoadStatus
} from "../api/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDateTime(iso: string | null): string {
  if (!iso) return "Never";
  return new Date(iso).toLocaleString();
}

function sourceName(source: PrimarySourceName): string {
  return source === "mitre" ? "MITRE ATT&CK" : "OpenCTI";
}

function statusColor(status: string): string {
  if (status === "completed") return "ok";
  if (status === "failed") return "error";
  return "pending";
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function SourceStatusPanel({
  status,
  ingesting,
  ingestError,
  onLoad
}: {
  status: SourceLoadStatus | null;
  ingesting: boolean;
  ingestError: string | null;
  onLoad: () => void;
}) {
  return (
    <div className="control-panel">
      <div className="field-group">
        <span>Active source</span>
        <p style={{ margin: 0, fontWeight: 700 }}>
          {status ? sourceName(status.source) : "—"}
        </p>
      </div>

      <div className="field-group">
        <span>Ingestion status</span>
        <p style={{ margin: 0 }}>
          <span className={`status ${status ? statusColor(status.status) : "pending"}`}>
            {status?.status ?? "unknown"}
          </span>
          {status?.version ? (
            <span style={{ marginLeft: 8, color: "#52606a", fontSize: "0.88rem" }}>
              v{status.version}
            </span>
          ) : null}
        </p>
      </div>

      {status && status.status === "completed" ? (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
          {[
            ["Actors", status.actor_count],
            ["Techniques", status.technique_count],
            ["Software", status.software_count]
          ].map(([label, count]) => (
            <div key={label as string} style={{ textAlign: "center" }}>
              <p style={{ margin: 0, fontWeight: 700, fontSize: "1.25rem" }}>{count}</p>
              <p style={{ margin: 0, color: "#52606a", fontSize: "0.82rem" }}>{label}</p>
            </div>
          ))}
        </div>
      ) : null}

      <div className="field-group">
        <span>Last loaded</span>
        <p style={{ margin: 0, color: "#52606a", fontSize: "0.88rem" }}>
          {formatDateTime(status?.last_loaded_at ?? null)}
        </p>
      </div>

      {status?.error ? (
        <div className="status-message error">
          <WifiOff size={16} aria-hidden="true" />
          <span>{status.error}</span>
        </div>
      ) : null}

      {ingestError ? (
        <div className="status-message error">
          <WifiOff size={16} aria-hidden="true" />
          <span>{ingestError}</span>
        </div>
      ) : null}

      <button className="primary-action" onClick={onLoad} disabled={ingesting} style={{ width: "100%" }}>
        {ingesting ? (
          <>
            <RefreshCw size={16} aria-hidden="true" style={{ animation: "spin 1s linear infinite" }} />
            Loading data…
          </>
        ) : (
          <>
            <RefreshCw size={16} aria-hidden="true" />
            {status?.status === "completed" ? "Reload data" : "Load data"}
          </>
        )}
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function SettingsPanel({
  health,
  error
}: {
  health: HealthResponse | null;
  error: string | null;
}) {
  const [settings, setSettings] = useState<ApplicationSettings | null>(null);
  const [sourceStatus, setSourceStatus] = useState<SourceLoadStatus | null>(null);
  const [loadingSettings, setLoadingSettings] = useState(true);

  // Form state — mirrors opencti config fields
  const [activeSource, setActiveSource] = useState<PrimarySourceName>("mitre");
  const [octiUrl, setOctiUrl] = useState("");
  const [octiToken, setOctiToken] = useState("");

  // Interaction state
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null);
  const [connectionVerified, setConnectionVerified] = useState(false);
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [ingesting, setIngesting] = useState(false);
  const [ingestError, setIngestError] = useState<string | null>(null);

  // Load settings + status on mount
  useEffect(() => {
    Promise.all([getSettings(), getSourceStatus()])
      .then(([s, st]) => {
        setSettings(s);
        setActiveSource(s.active_source);
        setOctiUrl(s.opencti.url ?? "");
        setOctiToken(s.opencti.api_token ?? "");
        setSourceStatus(st);
      })
      .catch(() => {})
      .finally(() => setLoadingSettings(false));
  }, []);

  // Reset verified state when form fields change
  function handleUrlChange(v: string) {
    setOctiUrl(v);
    setConnectionVerified(false);
    setTestResult(null);
  }
  function handleTokenChange(v: string) {
    setOctiToken(v);
    setConnectionVerified(false);
    setTestResult(null);
  }

  async function handleTest() {
    setTesting(true);
    setTestResult(null);
    setConnectionVerified(false);
    try {
      const result = await testSourceConnection(octiUrl, octiToken);
      setTestResult(result);
      setConnectionVerified(result.ok);
    } catch (err) {
      setTestResult({ ok: false, detail: err instanceof Error ? err.message : "Test failed" });
    } finally {
      setTesting(false);
    }
  }

  async function handleSave() {
    if (!settings) return;
    setSaving(true);
    setSaveError(null);
    try {
      const updated = await updateSettings({
        ...settings,
        active_source: activeSource,
        opencti: {
          ...settings.opencti,
          url: octiUrl || null,
          api_token: octiToken || null
        }
      });
      setSettings(updated);
      // Refresh status for the new active source
      const st = await getSourceStatus().catch(() => null);
      if (st) setSourceStatus(st);
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  async function handleLoadSource() {
    setIngesting(true);
    setIngestError(null);
    try {
      const st = await loadSource();
      setSourceStatus(st);
    } catch (err) {
      setIngestError(err instanceof Error ? err.message : "Ingestion failed");
    } finally {
      setIngesting(false);
    }
  }

  // Save button rules:
  // - MITRE: enabled whenever active_source changed to mitre (no credentials needed)
  // - OpenCTI: enabled only when test passed in this session and both fields non-empty
  const octiFormComplete = octiUrl.trim().length > 0 && octiToken.trim().length > 0;
  const saveEnabled =
    !saving &&
    (activeSource === "mitre" ||
      (activeSource === "opencti" && connectionVerified && octiFormComplete));

  // Load button: enabled when saved config has credentials (or MITRE always)
  const canLoad =
    !ingesting &&
    settings !== null &&
    (settings.active_source === "mitre" ||
      (settings.active_source === "opencti" &&
        Boolean(settings.opencti.url) &&
        Boolean(settings.opencti.api_token)));

  if (loadingSettings) {
    return (
      <section className="comparison-workspace" aria-labelledby="settings-title">
        <div className="workspace-header">
          <div>
            <p className="eyebrow">Settings</p>
            <h1 id="settings-title">Data source</h1>
          </div>
        </div>
        <div className="status-message neutral">
          <span>Loading settings…</span>
        </div>
      </section>
    );
  }

  return (
    <section className="comparison-workspace" aria-labelledby="settings-title">
      {/* Header */}
      <div className="workspace-header">
        <div>
          <p className="eyebrow">Settings</p>
          <h1 id="settings-title">Data source</h1>
        </div>
        <div className="source-pill">
          <Settings size={16} aria-hidden="true" />
          <span>Local backend</span>
        </div>
      </div>

      <div className="comparison-layout">
        {/* Left — configuration */}
        <div className="control-panel">
          {/* Source selector */}
          <div className="field-group">
            <span>Active source</span>
            <div className="action-row">
              <button
                className={activeSource === "mitre" ? "primary-action" : "secondary-action"}
                onClick={() => setActiveSource("mitre")}
                type="button"
              >
                MITRE ATT&CK
              </button>
              <button
                className={activeSource === "opencti" ? "primary-action" : "secondary-action"}
                onClick={() => setActiveSource("opencti")}
                type="button"
              >
                OpenCTI
              </button>
            </div>
          </div>

          {/* OpenCTI config form */}
          {activeSource === "opencti" ? (
            <>
              <div className="field-group">
                <label htmlFor="octi-url">Instance URL</label>
                <input
                  id="octi-url"
                  type="url"
                  placeholder="https://opencti.example.com"
                  value={octiUrl}
                  onChange={(e) => handleUrlChange(e.target.value)}
                  autoComplete="off"
                />
              </div>

              <div className="field-group">
                <label htmlFor="octi-token">API token</label>
                <input
                  id="octi-token"
                  type="password"
                  placeholder="••••••••••••"
                  value={octiToken}
                  onChange={(e) => handleTokenChange(e.target.value)}
                  autoComplete="new-password"
                />
              </div>

              <button
                className="secondary-action"
                onClick={handleTest}
                disabled={testing || !octiFormComplete}
                type="button"
                style={{ width: "100%" }}
              >
                {testing ? (
                  <>
                    <RefreshCw size={16} aria-hidden="true" style={{ animation: "spin 1s linear infinite" }} />
                    Testing…
                  </>
                ) : (
                  <>
                    <Wifi size={16} aria-hidden="true" />
                    Test connection
                  </>
                )}
              </button>

              {testResult !== null ? (
                <div className={`status-message ${testResult.ok ? "neutral" : "error"}`}>
                  {testResult.ok ? (
                    <Wifi size={16} aria-hidden="true" />
                  ) : (
                    <WifiOff size={16} aria-hidden="true" />
                  )}
                  <span>
                    {testResult.ok
                      ? "Connection successful"
                      : testResult.detail ?? "Connection failed"}
                  </span>
                </div>
              ) : null}
            </>
          ) : (
            <div className="status-message neutral">
              <Database size={16} aria-hidden="true" />
              <span>MITRE ATT&CK — no credentials required</span>
            </div>
          )}

          {saveError ? (
            <div className="status-message error">
              <WifiOff size={16} aria-hidden="true" />
              <span>{saveError}</span>
            </div>
          ) : null}

          <button
            className="primary-action"
            onClick={handleSave}
            disabled={!saveEnabled}
            type="button"
            style={{ width: "100%" }}
          >
            {saving ? "Saving…" : "Save configuration"}
          </button>

          {activeSource === "opencti" && !connectionVerified && octiFormComplete ? (
            <p style={{ margin: 0, color: "#52606a", fontSize: "0.85rem", textAlign: "center" }}>
              Test the connection first to enable saving
            </p>
          ) : null}
        </div>

        {/* Right — status + load */}
        <SourceStatusPanel
          status={sourceStatus}
          ingesting={ingesting || !canLoad}
          ingestError={ingestError}
          onLoad={handleLoadSource}
        />
      </div>

      {/* Backend health strip */}
      <div className="results-panel" style={{ padding: "16px 20px", minHeight: "auto" }}>
        <div className="results-header">
          <div>
            <p className="panel-label">Backend</p>
            <h2 style={{ fontSize: "1rem", margin: 0 }}>
              {health ? health.status : "Checking connection"}
            </h2>
          </div>
          <span className={health ? "metric-label status ok" : "metric-label status pending"}
            style={{ padding: "0 12px" }}>
            {health?.environment ?? "unknown"}
          </span>
        </div>
        {error ? (
          <p style={{ margin: "8px 0 0", color: "#b42318", fontSize: "0.88rem" }}>{error}</p>
        ) : null}
      </div>
    </section>
  );
}
