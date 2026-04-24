import { useEffect, useState } from "react";

import { getHealth } from "./api/client";
import type { HealthResponse } from "./api/types";
import { ActorComparisonPanel } from "./components/ActorComparisonPanel";
import { ActorMatrixHeatmapPanel } from "./components/ActorMatrixHeatmapPanel";
import { ActorNetworkGraphPanel } from "./components/ActorNetworkGraphPanel";
import { CustomTTPSetPanel } from "./components/CustomTTPSetPanel";
import { IncidentAnalysisPanel } from "./components/IncidentAnalysisPanel";
import { Layout, type ModuleKey } from "./components/Layout";
import { SettingsPanel } from "./components/SettingsPanel";
import "./styles.css";

function App() {
  const [activeModule, setActiveModule] = useState<ModuleKey>("compare");
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch((apiError: unknown) => {
        setError(apiError instanceof Error ? apiError.message : "Unable to reach backend");
      });
  }, []);

  return (
    <Layout activeModule={activeModule} onModuleChange={setActiveModule}>
      {activeModule === "compare" ? <ActorComparisonPanel /> : null}
      {activeModule === "ttp-profiles" ? (
        <div className="module-stack">
          <CustomTTPSetPanel />
          <IncidentAnalysisPanel />
        </div>
      ) : null}
      {activeModule === "visual-analysis" ? (
        <div className="module-stack">
          <ActorMatrixHeatmapPanel />
          <ActorNetworkGraphPanel />
        </div>
      ) : null}
      {activeModule === "settings" ? <SettingsPanel health={health} error={error} /> : null}
      <BackendStrip health={health} error={error} />
    </Layout>
  );
}

function BackendStrip({ health, error }: { health: HealthResponse | null; error: string | null }) {
  return (
    <footer className="backend-strip">
      <span className={health ? "status-dot ok" : "status-dot pending"} aria-hidden="true" />
      <span>Backend {health ? health.status : "checking"}</span>
      <span>{health?.environment ?? "unknown"}</span>
      {error ? <span className="error-text">{error}</span> : null}
    </footer>
  );
}

export default App;
