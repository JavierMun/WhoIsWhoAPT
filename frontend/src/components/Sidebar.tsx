import { Activity, Database, FileJson, Network, Settings } from "lucide-react";

import type { ModuleKey } from "./Layout";

const NAV_ITEMS: Array<{
  key: ModuleKey;
  label: string;
  icon: typeof Activity;
}> = [
  { key: "compare", label: "Compare", icon: Activity },
  { key: "ttp-profiles", label: "TTP Profiles", icon: FileJson },
  { key: "visual-analysis", label: "Explore", icon: Network },
  { key: "settings", label: "Settings", icon: Settings }
];

export function Sidebar({
  activeModule,
  onModuleChange
}: {
  activeModule: ModuleKey;
  onModuleChange: (module: ModuleKey) => void;
}) {
  return (
    <aside className="sidebar" aria-label="Application modules">
      <div className="brand">
        <Database size={22} aria-hidden="true" />
        <span>WhoIsWhoAPT</span>
      </div>
      <nav className="nav-list" aria-label="Primary">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = activeModule === item.key;
          return (
            <button
              className={`nav-item ${isActive ? "active" : ""}`}
              key={item.key}
              type="button"
              aria-current={isActive ? "page" : undefined}
              onClick={() => {
                onModuleChange(item.key);
              }}
            >
              <Icon size={18} aria-hidden="true" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>
    </aside>
  );
}
