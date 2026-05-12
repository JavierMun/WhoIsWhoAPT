import { CheckCircle, Database, Loader2, RefreshCw, Wifi, WifiOff, XCircle } from "lucide-react";
import { useEffect, useState } from "react";

import {
  getSettings,
  getSourceStatus,
  loadSource,
  testSourceConnection,
  updateSettings
} from "../api/client";
import { nextReloadLabel } from "../api/savedAnalysisUtils";
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
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(iso));
}

function sourceName(source: PrimarySourceName): string {
  return source === "mitre" ? "MITRE ATT&CK" : "OpenCTI";
}

function statusBadgeClass(status: string): string {
  if (status === "completed") return "status ok";
  if (status === "failed") return "status error";
  if (status === "running") return "status pending";
  return "status pending";
}

// ---------------------------------------------------------------------------
// Source Status Panel
// ---------------------------------------------------------------------------


function SourceStatusPanel({
  status,
  settings,
  ingesting,
  canLoad,
  ingestError,
  onLoad
}: {
  status: SourceLoadStatus | null;
  settings: ApplicationSettings | null;
  ingesting: boolean;
  canLoad: boolean;
  ingestError: string | null;
  onLoad: () => void;
}) {
  const hasData = status?.status === "completed";

  return (
    <div className="control-panel">
      <p className="panel-label" style={{ margin: "0 0 12px" }}>Dataset status</p>

      <div className="field-group">
        <span>Active source</span>
        <p style={{ margin: 0, fontWeight: 700 }}>
          {status ? sourceName(status.source) : "—"}
        </p>
      </div>

      <div className="field-group">
        <span>Status</span>
        <p style={{ margin: 0, display: "flex", alignItems: "center", gap: 8 }}>
          <span className={status ? statusBadgeClass(status.status) : "status pending"}>
            {status?.status ?? "never loaded"}
          </span>
          {status?.version ? (
            <span style={{ color: "var(--text-3)", fontSize: "0.85rem" }}>v{status.version}</span>
          ) : null}
        </p>
      </div>

      <div className="field-group">
        <span>Last loaded</span>
        <p style={{ margin: 0, color: "var(--text-3)", fontSize: "0.88rem" }}>
          {formatDateTime(status?.last_loaded_at ?? null)}
        </p>
      </div>

      {settings ? (
        <div className="field-group">
          <span>Next auto-reload</span>
          <p style={{ margin: 0, color: "var(--text-3)", fontSize: "0.88rem" }}>
            {settings.active_source === "mitre"
              ? nextReloadLabel(status?.last_loaded_at ?? null, settings.mitre.update_frequency_hours, settings.mitre.auto_update)
              : nextReloadLabel(status?.last_loaded_at ?? null, settings.opencti.update_frequency_hours, settings.opencti.auto_update)}
          </p>
        </div>
      ) : null}

      {hasData ? (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
          {[
            ["Actors", status!.actor_count],
            ["Campaigns", status!.campaign_count],
            ["Software", status!.software_count],
            ["Techniques", status!.technique_count]
          ].map(([label, count]) => (
            <div
              key={label as string}
              style={{
                textAlign: "center",
                padding: "10px 8px",
                background: "var(--bg-3)",
                border: "1px solid var(--border-bright)",
                borderRadius: "var(--radius)"
              }}
            >
              <p style={{ margin: 0, fontWeight: 700, fontSize: "1.2rem", color: "var(--accent-text)" }}>{count}</p>
              <p style={{ margin: 0, color: "var(--text-3)", fontSize: "0.78rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>{label}</p>
            </div>
          ))}
        </div>
      ) : null}

      {status?.error ? (
        <div className="status-message error">
          <XCircle size={16} aria-hidden="true" />
          <span>{status.error}</span>
        </div>
      ) : null}

      {ingestError ? (
        <div className="status-message error">
          <XCircle size={16} aria-hidden="true" />
          <span>{ingestError}</span>
        </div>
      ) : null}

      {canLoad ? (
        <button
          className="primary-action"
          onClick={onLoad}
          disabled={ingesting}
          type="button"
          style={{ width: "100%" }}
        >
          {ingesting ? (
            <>
              <Loader2 size={16} aria-hidden="true" style={{ animation: "spin 1s linear infinite" }} />
              Loading data…
            </>
          ) : (
            <>
              <RefreshCw size={16} aria-hidden="true" />
              {hasData ? "Reload data" : "Load data"}
            </>
          )}
        </button>
      ) : (
        <p style={{ margin: 0, fontSize: "0.85rem", color: "#70808a", textAlign: "center" }}>
          Save a valid configuration to enable data loading.
        </p>
      )}
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

  // Form state
  const [activeSource, setActiveSource] = useState<PrimarySourceName>("mitre");
  const [octiUrl, setOctiUrl] = useState("");
  const [octiToken, setOctiToken] = useState("");

  // Interaction state
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null);
  const [connectionVerified, setConnectionVerified] = useState(false);
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [ingesting, setIngesting] = useState(false);
  const [ingestError, setIngestError] = useState<string | null>(null);

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

  function handleSourceChange(source: PrimarySourceName) {
    setActiveSource(source);
    // Reset test state when switching sources
    setTestResult(null);
    setConnectionVerified(false);
    setSaveSuccess(false);
    setSaveError(null);
  }

  async function handleTest() {
    setTesting(true);
    setTestResult(null);
    setConnectionVerified(false);
    try {
      const result = await testSourceConnection(octiUrl.trim(), octiToken.trim());
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
    setSaveSuccess(false);
    try {
      const updated = await updateSettings({
        ...settings,
        active_source: activeSource,
        opencti: {
          ...settings.opencti,
          url: activeSource === "opencti" ? (octiUrl.trim() || null) : settings.opencti.url,
          api_token: activeSource === "opencti" ? (octiToken.trim() || null) : settings.opencti.api_token
        }
      });
      setSettings(updated);
      setSaveSuccess(true);
      // Refresh status for new active source
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

  const octiFormComplete = octiUrl.trim().length > 0 && octiToken.trim().length > 0;

  // Save is enabled when:
  // - MITRE: always (no credentials required)
  // - OpenCTI: only after a successful connection test with both fields filled
  const saveEnabled =
    !saving &&
    (activeSource === "mitre" ||
      (activeSource === "opencti" && connectionVerified && octiFormComplete));

  // Load data is only available when the SAVED config has credentials (or is MITRE)
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
        <div className="status-message neutral" style={{ margin: "24px 0" }}>
          <Loader2 size={16} style={{ animation: "spin 1s linear infinite" }} aria-hidden="true" />
          <span>Loading settings…</span>
        </div>
      </section>
    );
  }

  return (
    <section className="comparison-workspace" aria-labelledby="settings-title">
      <div className="workspace-header">
        <div>
          <p className="eyebrow">Settings</p>
          <h1 id="settings-title">Data source</h1>
        </div>
      </div>

      <div className="comparison-layout">
        {/* ── Left: configuration ─────────────────────────────────── */}
        <div className="control-panel">

          {/* Source selector */}
          <fieldset className="scope-selector" style={{ marginBottom: 0 }}>
            <legend>Active source</legend>
            <label>
              <input
                type="radio"
                name="active-source"
                value="mitre"
                checked={activeSource === "mitre"}
                onChange={() => handleSourceChange("mitre")}
              />
              <span>MITRE ATT&CK</span>
            </label>
            <label>
              <input
                type="radio"
                name="active-source"
                value="opencti"
                checked={activeSource === "opencti"}
                onChange={() => handleSourceChange("opencti")}
              />
              <span>OpenCTI</span>
            </label>
          </fieldset>

          {/* MITRE info */}
          {activeSource === "mitre" ? (
            <div className="status-message neutral">
              <Database size={16} aria-hidden="true" />
              <span>MITRE ATT&CK — no credentials required. Data is bundled with the application.</span>
            </div>
          ) : null}

          {/* OpenCTI config */}
          {activeSource === "opencti" ? (
            <>
              <div className="field-group">
                <label htmlFor="octi-url">Instance URL</label>
                <input
                  id="octi-url"
                  type="url"
                  placeholder="http://localhost:8080"
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
                  placeholder="••••••••••••••••"
                  value={octiToken}
                  onChange={(e) => handleTokenChange(e.target.value)}
                  autoComplete="new-password"
                />
              </div>

              <button
                className="secondary-action"
                onClick={() => void handleTest()}
                disabled={testing || !octiFormComplete}
                type="button"
                style={{ width: "100%" }}
              >
                {testing ? (
                  <>
                    <Loader2 size={16} aria-hidden="true" style={{ animation: "spin 1s linear infinite" }} />
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
                <div className={`status-message ${testResult.ok ? "success" : "error"}`}>
                  {testResult.ok ? (
                    <CheckCircle size={16} aria-hidden="true" />
                  ) : (
                    <WifiOff size={16} aria-hidden="true" />
                  )}
                  <span>
                    {testResult.ok
                      ? "Connection successful — you can now save the configuration."
                      : (testResult.detail ?? "Connection failed. Check the URL and API token.")}
                  </span>
                </div>
              ) : null}

              {!connectionVerified && octiFormComplete && testResult === null ? (
                <p style={{ margin: 0, color: "#70808a", fontSize: "0.82rem" }}>
                  Test the connection before saving.
                </p>
              ) : null}
            </>
          ) : null}

          {/* Save feedback */}
          {saveSuccess ? (
            <div className="status-message success">
              <CheckCircle size={16} aria-hidden="true" />
              <span>Configuration saved.</span>
            </div>
          ) : null}

          {saveError ? (
            <div className="status-message error">
              <XCircle size={16} aria-hidden="true" />
              <span>{saveError}</span>
            </div>
          ) : null}

          {/* Save button */}
          <button
            className="primary-action"
            onClick={() => void handleSave()}
            disabled={!saveEnabled}
            type="button"
            style={{ width: "100%" }}
          >
            {saving ? (
              <>
                <Loader2 size={16} aria-hidden="true" style={{ animation: "spin 1s linear infinite" }} />
                Saving…
              </>
            ) : (
              "Save configuration"
            )}
          </button>
        </div>

        {/* ── Right: status + load ─────────────────────────────────── */}
        <SourceStatusPanel
          status={sourceStatus}
          settings={settings}
          ingesting={ingesting}
          canLoad={canLoad}
          ingestError={ingestError}
          onLoad={() => void handleLoadSource()}
        />
      </div>

      {/* Backend health strip */}
      <div className="results-panel" style={{ padding: "14px 20px", minHeight: "auto", marginTop: 0 }}>
        <div className="results-header" style={{ marginBottom: 0 }}>
          <div>
            <p className="panel-label">Backend service</p>
            <p style={{ margin: 0, fontWeight: 600, fontSize: "0.95rem" }}>
              {health ? `Status: ${health.status}` : "Connecting…"}
            </p>
          </div>
          <span
            className="metric-label"
          >
            {health?.environment ?? "unknown"}
          </span>
        </div>
        {error ? (
          <p style={{ margin: "8px 0 0", color: "#b42318", fontSize: "0.85rem" }}>{error}</p>
        ) : null}
      </div>
    </section>
  );
}
