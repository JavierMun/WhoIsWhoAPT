import { Activity, FileJson, Network, Settings } from "lucide-react";
import { useEffect, useState } from "react";

import { getAnalyses, getTTPProfiles } from "../api/client";
import type { AnalysisResponse, HealthResponse, PrimarySourceName } from "../api/types";
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
  activeSource,
  actorCount
}: {
  activeModule: ModuleKey;
  onModuleChange: (module: ModuleKey) => void;
  health: HealthResponse | null;
  activeSource: PrimarySourceName;
  actorCount?: number;
}) {
  const [recentAnalyses, setRecentAnalyses] = useState<AnalysisResponse[]>([]);
  const [profileCount, setProfileCount] = useState<number | null>(null);
  const [analysisCount, setAnalysisCount] = useState<number | null>(null);

  useEffect(() => {
    getAnalyses()
      .then((analyses) => {
        setRecentAnalyses(analyses.slice(0, 2));
        setAnalysisCount(analyses.length);
      })
      .catch(() => {});
    getTTPProfiles()
      .then((profiles) => setProfileCount(profiles.length))
      .catch(() => {});
  }, []);

  const badges: Partial<Record<ModuleKey, number | null>> = {
    "compare": analysisCount,
    "ttp-profiles": profileCount
  };

  return (
    <aside className="sidebar" aria-label="Application modules">
      {/* Brand */}
      <div className="brand">
        <img src="/logo.png" alt="WhoIsWhoAPT logo" className="brand-logo-img" />
        <div>
          <div className="brand-name">WhoIsWhoAPT</div>
          <div className="brand-sub">{activeSource === "mitre" ? "ATT&CK" : "OpenCTI"}</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="nav-list" aria-label="Primary navigation">
        <p className="sidebar-section-label">Workspace</p>
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = activeModule === item.key;
          const badge = badges[item.key];
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
              {badge != null && badge > 0 ? (
                <span className="nav-badge">{badge}</span>
              ) : null}
            </button>
          );
        })}

        {/* Recent analyses */}
        {recentAnalyses.length > 0 ? (
          <>
            <p className="sidebar-section-label" style={{ marginTop: 16 }}>Recent</p>
            {recentAnalyses.map((analysis) => (
              <button
                key={analysis.id}
                className="nav-item nav-item--recent"
                type="button"
                onClick={() => onModuleChange("compare")}
                title={analysis.input_name}
              >
                <span className="nav-item-recent-icon" aria-hidden="true">◎</span>
                <span className="nav-item-recent-name">
                  {analysis.input_name.length > 22
                    ? `${analysis.input_name.slice(0, 22)}…`
                    : analysis.input_name}
                </span>
              </button>
            ))}
          </>
        ) : null}
      </nav>

      {/* Footer health card */}
      <div className="sidebar-footer">
        <div className="health-card">
          <div className="health-card-row">
            <span className="health-card-label">Backend</span>
            <span className="health-card-value">
              <span className={`status-dot ${health ? "ok" : "pending"}`} aria-hidden="true" />
              {health ? health.status.toUpperCase() : "connecting"}
            </span>
          </div>
          <div className="health-card-row">
            <span className="health-card-label">Source</span>
            <span className="health-card-value">
              {activeSource === "mitre" ? "MITRE ATT&CK" : "OpenCTI"}
            </span>
          </div>
          {actorCount != null ? (
            <div className="health-card-row">
              <span className="health-card-label">Actors</span>
              <span className="health-card-value">{actorCount}</span>
            </div>
          ) : null}
        </div>
      </div>
    </aside>
  );
}
