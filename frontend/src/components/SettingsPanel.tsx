import { Database, Settings } from "lucide-react";

import type { HealthResponse } from "../api/types";

export function SettingsPanel({ health, error }: { health: HealthResponse | null; error: string | null }) {
  return (
    <section className="comparison-workspace" aria-labelledby="settings-title">
      <div className="workspace-header">
        <div>
          <p className="eyebrow">Settings</p>
          <h1 id="settings-title">Data source status</h1>
        </div>
        <div className="source-pill">
          <Settings size={16} aria-hidden="true" />
          <span>Local backend</span>
        </div>
      </div>

      <section className="results-panel settings-panel" aria-live="polite">
        <div className="results-header">
          <div>
            <p className="panel-label">Backend</p>
            <h2>{health ? health.status : "Checking connection"}</h2>
          </div>
          <span className={health ? "metric-label status ok" : "metric-label status pending"}>
            {health?.environment ?? "unknown"}
          </span>
        </div>
        <div className="settings-status">
          <Database size={24} aria-hidden="true" />
          <div>
            <strong>Active source</strong>
            <p>MITRE dataset</p>
          </div>
          <div>
            <strong>Connection</strong>
            <p>{error ?? (health ? "Backend API reachable" : "Waiting for backend health response")}</p>
          </div>
        </div>
      </section>
    </section>
  );
}
