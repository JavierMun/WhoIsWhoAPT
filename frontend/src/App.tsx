import { Activity, Database, Settings } from "lucide-react";
import { useEffect, useState } from "react";

import { getHealth } from "./api/client";
import type { HealthResponse } from "./api/types";
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
            <span>Status</span>
          </a>
          <a className="nav-item disabled" href="/settings" aria-disabled="true">
            <Settings size={18} aria-hidden="true" />
            <span>Settings</span>
          </a>
        </nav>
      </aside>

      <section className="content-area">
        <header className="page-header">
          <p className="eyebrow">Foundation</p>
          <h1>Local threat intelligence workspace</h1>
        </header>

        <div className="status-panel">
          <div>
            <p className="panel-label">Backend</p>
            <p className={health ? "status ok" : "status pending"}>{health ? health.status : "checking"}</p>
          </div>
          <div>
            <p className="panel-label">Environment</p>
            <p>{health?.environment ?? "unknown"}</p>
          </div>
          <div>
            <p className="panel-label">Service</p>
            <p>{health?.service ?? "WhoIsWhoAPT"}</p>
          </div>
          {error ? <p className="error-text">{error}</p> : null}
        </div>
      </section>
    </main>
  );
}

export default App;

