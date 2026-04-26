import { BarChart3, Download, FileJson, GitGraph, Table } from "lucide-react";
import { useState } from "react";

import { downloadComparisonExport } from "../api/exportUtils";
import type { TechniqueLookup } from "../api/ttpProfileUtils";
import type { ActorComparisonResponse, SimilarityMetric } from "../api/types";
import { ComparisonGraphView } from "./ComparisonGraphView";
import { ComparisonHeatmapView } from "./ComparisonHeatmapView";
import { ComparisonRankingView } from "./ComparisonRankingView";

type ComparisonView = "ranking" | "heatmap" | "graph";

export function ComparisonResultTabs({
  comparison,
  topN,
  comparisonScopeLabel,
  tacticScopeLabel,
  techniqueLookup
}: {
  comparison: ActorComparisonResponse;
  topN: number;
  comparisonScopeLabel: string;
  tacticScopeLabel: string;
  techniqueLookup: TechniqueLookup;
}) {
  const [activeView, setActiveView] = useState<ComparisonView>("ranking");

  return (
    <section className="results-panel comparison-results-panel" aria-live="polite">
      <div className="results-header comparison-results-header">
        <div>
          <p className="panel-label">Source profile</p>
          <h2>{comparison.input_name}</h2>
          <p className="scope-summary">Comparing against: {comparisonScopeLabel}</p>
          <p className="scope-summary">Similarity scope: {tacticScopeLabel}</p>
        </div>
        <div className="results-actions">
          <span className="metric-label">{metricLabel(comparison.metric)}</span>
          <button
            type="button"
            title="Export JSON"
            onClick={() => downloadComparisonExport(comparison, "json", "mitre", topN, techniqueLookup)}
          >
            <FileJson size={16} aria-hidden="true" />
          </button>
          <button
            type="button"
            title="Export CSV"
            onClick={() => downloadComparisonExport(comparison, "csv", "mitre", topN, techniqueLookup)}
          >
            <Table size={16} aria-hidden="true" />
          </button>
          <button
            type="button"
            title="Export Navigator layer"
            onClick={() => downloadComparisonExport(comparison, "navigator", "mitre", topN, techniqueLookup)}
          >
            <Download size={16} aria-hidden="true" />
          </button>
        </div>
      </div>

      <div className="comparison-tabs" role="tablist" aria-label="Comparison result views">
        <TabButton active={activeView === "ranking"} label="Ranking" onClick={() => setActiveView("ranking")} />
        <TabButton active={activeView === "heatmap"} label="Heatmap" onClick={() => setActiveView("heatmap")} />
        <TabButton active={activeView === "graph"} label="Graph" onClick={() => setActiveView("graph")} />
      </div>

      <div className="comparison-tab-body">
        {activeView === "ranking" ? <ComparisonRankingView comparison={comparison} techniqueLookup={techniqueLookup} /> : null}
        {activeView === "heatmap" ? <ComparisonHeatmapView comparison={comparison} /> : null}
        {activeView === "graph" ? <ComparisonGraphView comparison={comparison} /> : null}
      </div>
    </section>
  );
}

function TabButton({ active, label, onClick }: { active: boolean; label: string; onClick: () => void }) {
  return (
    <button className={active ? "active" : ""} type="button" role="tab" aria-selected={active} onClick={onClick}>
      {label === "Ranking" ? <BarChart3 size={16} aria-hidden="true" /> : null}
      {label === "Heatmap" ? <Table size={16} aria-hidden="true" /> : null}
      {label === "Graph" ? <GitGraph size={16} aria-hidden="true" /> : null}
      <span>{label}</span>
    </button>
  );
}

function metricLabel(metric: SimilarityMetric): string {
  if (metric === "jaccard_weighted") {
    return "Weighted Jaccard";
  }
  if (metric === "tactic_weighted_jaccard") {
    return "Tactic weighted";
  }
  if (metric === "software_weighted_jaccard") {
    return "Software weighted";
  }
  return "Jaccard";
}
