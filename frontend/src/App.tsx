import { useEffect, useState } from "react";

import { getHealth, getSettings } from "./api/client";
import type { HealthResponse, PrimarySourceName } from "./api/types";
import { ActorComparisonPanel } from "./components/ActorComparisonPanel";
import { ActorMatrixHeatmapPanel } from "./components/ActorMatrixHeatmapPanel";
import { ActorNetworkGraphPanel } from "./components/ActorNetworkGraphPanel";
import { ActorSimilarityPanel } from "./components/ActorSimilarityPanel";
import { Layout, type ModuleKey } from "./components/Layout";
import { SettingsPanel } from "./components/SettingsPanel";
import { TTPProfilesPanel } from "./components/TTPProfilesPanel";
import "./styles.css";

function App() {
  const [activeModule, setActiveModule] = useState<ModuleKey>("compare");
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeSource, setActiveSource] = useState<PrimarySourceName>("mitre");
  const [actorCount, setActorCount] = useState<number | undefined>(undefined);

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
    <Layout
      activeModule={activeModule}
      onModuleChange={setActiveModule}
      health={health}
      activeSource={activeSource}
      actorCount={actorCount}
    >
      {activeModule === "compare" ? <ActorComparisonPanel activeSource={activeSource} onActorCountChange={setActorCount} /> : null}
      {activeModule === "ttp-profiles" ? <TTPProfilesPanel activeSource={activeSource} /> : null}
      {activeModule === "visual-analysis" ? (
        <div className="module-stack">
          <ActorSimilarityPanel />
          <ActorMatrixHeatmapPanel />
          <ActorNetworkGraphPanel />
        </div>
      ) : null}
      {activeModule === "settings" ? <SettingsPanel health={health} error={error} /> : null}
    </Layout>
  );
}

export default App;
