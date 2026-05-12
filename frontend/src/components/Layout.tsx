import type { ReactNode } from "react";

import type { HealthResponse, PrimarySourceName } from "../api/types";
import { Sidebar } from "./Sidebar";

export type ModuleKey = "compare" | "ttp-profiles" | "visual-analysis" | "settings";

export function Layout({
  activeModule,
  onModuleChange,
  health,
  activeSource,
  actorCount,
  children
}: {
  activeModule: ModuleKey;
  onModuleChange: (module: ModuleKey) => void;
  health: HealthResponse | null;
  activeSource: PrimarySourceName;
  actorCount?: number;
  children: ReactNode;
}) {
  return (
    <main className="app-shell">
      <Sidebar
        activeModule={activeModule}
        onModuleChange={onModuleChange}
        health={health}
        activeSource={activeSource}
        actorCount={actorCount}
      />
      <section className="content-area">{children}</section>
    </main>
  );
}
