import type { ReactNode } from "react";

import type { HealthResponse, PrimarySourceName } from "../api/types";
import { Sidebar } from "./Sidebar";

export type ModuleKey = "compare" | "ttp-profiles" | "visual-analysis" | "settings";

export function Layout({
  activeModule,
  onModuleChange,
  health,
  activeSource,
  children
}: {
  activeModule: ModuleKey;
  onModuleChange: (module: ModuleKey) => void;
  health: HealthResponse | null;
  activeSource: PrimarySourceName;
  children: ReactNode;
}) {
  return (
    <main className="app-shell">
      <Sidebar
        activeModule={activeModule}
        onModuleChange={onModuleChange}
        health={health}
        activeSource={activeSource}
      />
      <section className="content-area">{children}</section>
    </main>
  );
}
