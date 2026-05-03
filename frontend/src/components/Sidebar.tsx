import { Activity, FileJson, Network, Settings } from "lucide-react";

import type { HealthResponse, PrimarySourceName } from "../api/types";
import type { ModuleKey } from "./Layout";

const NAV_ITEMS: Array<{ key: ModuleKey; label: string; icon: typeof Activity }> = [
  { key: "compare",         label: "Compare",      icon: Activity },
  { key: "ttp-profiles",    label: "TTP Profiles",  icon: FileJson },
  { key: "visual-analysis", label: "Explore",       icon: Network },
  { key: "settings",        label: "Settings",      icon: Settings }
];

export function Sidebar({
  activeModule,
  onModuleChange,
  health,
  activeSource
}: {
  activeModule: ModuleKey;
  onModuleChange: (module: ModuleKey) => void;
  health: HealthResponse | null;
  activeSource: PrimarySourceName;
}) {
  return (
    <aside className="sidebar" aria-label="Application modules">
      {/* Brand */}
      <div className="brand">
        <div className="brand-logo" aria-hidden="true">🐙</div>
        <div>
          <div className="brand-name">WhoIsWhoAPT</div>
          <div className="brand-sub">CTI Analysis</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="nav-list" aria-label="Primary navigation">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = activeModule === item.key;
          return (
            <button
              className={`nav-item${isActive ? " active" : ""}`}
              key={item.key}
              type="button"
              aria-current={isActive ? "page" : undefined}
              onClick={() => onModuleChange(item.key)}
            >
              <Icon size={16} aria-hidden="true" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Footer health card */}
      <div className="sidebar-footer">
        <div className="health-card">
          <div className="health-card-row">
            <span className="health-card-label">Backend</span>
            <span className="health-card-value">
              <span
                className={`status-dot ${health ? "ok" : "pending"}`}
                aria-hidden="true"
              />
              {health ? health.status : "connecting"}
            </span>
          </div>
          <div className="health-card-row">
            <span className="health-card-label">Source</span>
            <span className="health-card-value">
              {activeSource === "mitre" ? "MITRE ATT\&CK" : "OpenCTI"}
            </span>
          </div>
          {health?.environment ? (
            <div className="health-card-row">
              <span className="health-card-label">Env</span>
              <span className="health-card-value">{health.environment}</span>
            </div>
          ) : null}
        </div>
      </div>
    </aside>
  );
}
