import { useEffect, useState } from "react";

import { getHealth, getSettings } from "./api/client";
import type { HealthResponse, PrimarySourceName } from "./api/types";
import { ActorComparisonPanel } from "./components/ActorComparisonPanel";
import { ActorMatrixHeatmapPanel } from "./components/ActorMatrixHeatmapPanel";
import { ActorNetworkGraphPanel } from "./components/ActorNetworkGraphPanel";
import { Layout, type ModuleKey } from "./components/Layout";
import { SettingsPanel } from "./components/SettingsPanel";
import { TTPProfilesPanel } from "./components/TTPProfilesPanel";
import "./styles.css";

function App() {
  const [activeModule, setActiveModule] = useState<ModuleKey>("compare");
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeSource, setActiveSource] = useState<PrimarySourceName>("mitre");

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch((apiError: unknown) => {
        setError(apiError instanceof Error ? apiError.message : "Unable to reach backend");
      });
    getSettings()
      .then((s) => setActiveSource(s.active_source))
      .catch(() => {});
  }, []);

  return (
    <Layout activeModule={activeModule} onModuleChange={setActiveModule}>
      {activeModule === "compare" ? <ActorComparisonPanel activeSource={activeSource} /> : null}
      {activeModule === "ttp-profiles" ? <TTPProfilesPanel activeSource={activeSource} /> : null}
      {activeModule === "visual-analysis" ? (
        <div className="module-stack">
          <ActorMatrixHeatmapPanel />
          <ActorNetworkGraphPanel />
        </div>
      ) : null}
      {activeModule === "settings" ? <SettingsPanel health={health} error={error} /> : null}
      <BackendStrip health={health} error={error} activeSource={activeSource} />
    </Layout>
  );
}

function BackendStrip({
  health,
  error,
  activeSource
}: {
  health: HealthResponse | null;
  error: string | null;
  activeSource: PrimarySourceName;
}) {
  const sourceLabel = activeSource === "mitre" ? "MITRE ATT&CK" : "OpenCTI";
  return (
    <footer className="backend-strip">
      <span className={health ? "status-dot ok" : "status-dot pending"} aria-hidden="true" />
      <span>Backend {health ? health.status : "checking"}</span>
      <span>{health?.environment ?? "unknown"}</span>
      <span style={{ marginLeft: "auto", opacity: 0.7, fontSize: "0.8rem" }}>
        Source: {sourceLabel}
      </span>
      {error ? <span className="error-text">{error}</span> : null}
    </footer>
  );
}

export default App;
