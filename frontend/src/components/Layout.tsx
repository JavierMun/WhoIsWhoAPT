import type { ReactNode } from "react";

import { Sidebar } from "./Sidebar";

export type ModuleKey = "compare" | "ttp-profiles" | "visual-analysis" | "settings";

export function Layout({
  activeModule,
  onModuleChange,
  children
}: {
  activeModule: ModuleKey;
  onModuleChange: (module: ModuleKey) => void;
  children: ReactNode;
}) {
  return (
    <main className="app-shell">
      <Sidebar activeModule={activeModule} onModuleChange={onModuleChange} />
      <section className="content-area">{children}</section>
    </main>
  );
}
