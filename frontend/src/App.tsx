import { Activity, Database, Settings } from "lucide-react";
import { useEffect, useState } from "react";

import { getHealth } from "./api/client";
import type { HealthResponse } from "./api/types";
import { ActorComparisonPanel } from "./components/ActorComparisonPanel";
import { CustomTTPSetPanel } from "./components/CustomTTPSetPanel";
import "./styles.css";

function App() {
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
    <main className="app-shell">
      <aside className="sidebar" aria-label="Application sections">
        <div className="brand">
          <Database size={22} aria-hidden="true" />
          <span>WhoIsWhoAPT</span>
        </div>
        <nav className="nav-list">
          <a className="nav-item active" href="/">
            <Activity size={18} aria-hidden="true" />
            <span>Compare</span>
          </a>
          <a className="nav-item disabled" href="/settings" aria-disabled="true">
            <Settings size={18} aria-hidden="true" />
            <span>Settings</span>
          </a>
        </nav>
      </aside>

      <section className="content-area">
        <ActorComparisonPanel />
        <CustomTTPSetPanel />

        <footer className="backend-strip">
          <span className={health ? "status-dot ok" : "status-dot pending"} aria-hidden="true" />
          <span>Backend {health ? health.status : "checking"}</span>
          <span>{health?.environment ?? "unknown"}</span>
          {error ? <span className="error-text">{error}</span> : null}
        </footer>
      </section>
    </main>
  );
}

export default App;
