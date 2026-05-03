import { BarChart3, ChevronDown, ChevronRight, Download, FileJson, GitGraph, Save, Table } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { getActorDetail, saveAnalysis } from "../api/client";
import { downloadComparisonExport } from "../api/exportUtils";
import { formatTactic, groupTechniquesByTactic, splitTactics, type TechniqueLookup } from "../api/ttpProfileUtils";
import type { ActorComparisonResponse, ActorDetail, SimilarityMetric } from "../api/types";
import { ComparisonGraphView } from "./ComparisonGraphView";
import { ComparisonHeatmapView } from "./ComparisonHeatmapView";
import { ComparisonRankingView } from "./ComparisonRankingView";

type ComparisonView = "ranking" | "heatmap" | "graph";

export function ComparisonResultTabs({
  comparison,
  topN,
  comparisonScopeLabel,
  tacticScopeLabel,
  tactics,
  targetIds,
  canSave = true,
  onAnalysisSaved,
  techniqueLookup
}: {
  comparison: ActorComparisonResponse;
  topN: number;
  comparisonScopeLabel: string;
  tacticScopeLabel: string;
  tactics?: string[];
  targetIds?: string[];
  canSave?: boolean;
  onAnalysisSaved?: () => void;
  techniqueLookup: TechniqueLookup;
}) {
  const [activeView, setActiveView] = useState<ComparisonView>("ranking");
  const [savingAnalysis, setSavingAnalysis] = useState(false);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [inputDetail, setInputDetail] = useState<ActorDetail | null>(null);

  useEffect(() => {
    setInputDetail(null);
    if (comparison.input_type === "actor" && comparison.input_id) {
      getActorDetail(comparison.input_id).then(setInputDetail).catch(() => {});
    }
  }, [comparison.input_id, comparison.input_type]);

  async function handleSaveAnalysis() {
    if (savingAnalysis) return;
    setSavingAnalysis(true);
    setSaveMessage(null);
    setSaveError(null);
    try {
      const saved = await saveAnalysis({
        input_type: comparison.input_type === "actor" ? "actor" : "custom",
        input_id: comparison.input_id,
        input_name: comparison.input_name,
        metric: comparison.metric,
        tactics,
        target_ids: targetIds,
        top_n: topN,
        results: comparison
      });
      setSaveMessage(`Saved analysis ${saved.id.slice(0, 8)}.`);
      onAnalysisSaved?.();
    } catch (apiError) {
      setSaveError(apiError instanceof Error ? apiError.message : "Unable to save analysis");
    } finally {
      setSavingAnalysis(false);
    }
  }

  return (
    <section className="results-panel comparison-results-panel" aria-live="polite">
      <div className="results-header comparison-results-header">
        <div>
          <p className="panel-label">Source profile</p>
          <h2>{comparison.input_name}</h2>
          <p className="scope-summary">Comparing against: {comparisonScopeLabel}</p>
          <p className="scope-summary">Similarity scope: {tacticScopeLabel}</p>
          <SourceProfilePanel
            detail={inputDetail}
            inputName={comparison.input_name}
            techniqueLookup={techniqueLookup}
          />
        </div>
        <div className="results-actions">
          <span className="metric-label">{metricLabel(comparison.metric)}</span>
          {canSave ? (
            <button
              className="save-analysis-button"
              type="button"
              title="Save analysis"
              disabled={savingAnalysis}
              onClick={() => void handleSaveAnalysis()}
            >
              <Save size={16} aria-hidden="true" />
              <span>{savingAnalysis ? "Saving" : "Save analysis"}</span>
            </button>
          ) : null}
          <button type="button" title="Export JSON" onClick={() => downloadComparisonExport(comparison, "json", "mitre", topN, techniqueLookup)}>
            <FileJson size={16} aria-hidden="true" />
          </button>
          <button type="button" title="Export CSV" onClick={() => downloadComparisonExport(comparison, "csv", "mitre", topN, techniqueLookup)}>
            <Table size={16} aria-hidden="true" />
          </button>
          <button type="button" title="Export Navigator layer" onClick={() => downloadComparisonExport(comparison, "navigator", "mitre", topN, techniqueLookup)}>
            <Download size={16} aria-hidden="true" />
          </button>
        </div>
      </div>
      {saveMessage ? <div className="analysis-save-status success">{saveMessage}</div> : null}
      {saveError ? <div className="analysis-save-status error">{saveError}</div> : null}

      <div className="comparison-tabs" role="tablist" aria-label="Comparison result views">
        <TabButton active={activeView === "ranking"} label="Ranking" onClick={() => setActiveView("ranking")} />
        <TabButton active={activeView === "heatmap"} label="Heatmap" onClick={() => setActiveView("heatmap")} />
        <TabButton active={activeView === "graph"} label="Graph" onClick={() => setActiveView("graph")} />
      </div>

      <div className="comparison-tab-body">
        {activeView === "ranking" ? (
          <ComparisonRankingView
            comparison={comparison}
            techniqueLookup={techniqueLookup}
            inputSectors={inputDetail?.target_sectors ?? []}
            inputCountries={inputDetail?.target_countries ?? []}
          />
        ) : null}
        {activeView === "heatmap" ? <ComparisonHeatmapView comparison={comparison} /> : null}
        {activeView === "graph" ? <ComparisonGraphView comparison={comparison} /> : null}
      </div>
    </section>
  );
}

function SourceProfilePanel({
  detail,
  inputName,
  techniqueLookup
}: {
  detail: ActorDetail | null;
  inputName: string;
  techniqueLookup: TechniqueLookup;
}) {
  const [open, setOpen] = useState(false);

  const tacticGroups = useMemo(() => {
    if (!detail) return [];
    const ids = detail.techniques.map((t) => t.technique_id);
    return groupTechniquesByTactic(ids, techniqueLookup);
  }, [detail, techniqueLookup]);

  if (!detail) return null;

  const hasEnrichment =
    detail.description ||
    detail.target_sectors.length > 0 ||
    detail.target_countries.length > 0;

  return (
    <div className="source-profile-panel">
      <button
        type="button"
        className="breakdown-toggle"
        style={{ marginTop: 6 }}
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        {open ? <ChevronDown size={14} aria-hidden="true" /> : <ChevronRight size={14} aria-hidden="true" />}
        {inputName} details
      </button>

      {open ? (
        <div className="source-profile-body">
          {detail.description ? (
            <p className="source-profile-description">{detail.description}</p>
          ) : null}

          {detail.motivation ? (
            <div className="source-profile-section">
              <span className="actor-context-label">Motivation</span>
              <div className="chip-list" style={{ marginTop: 4 }}>
                <span className="technique-chip">{detail.motivation}</span>
              </div>
            </div>
          ) : null}

          <div className="source-profile-section">
            <span className="actor-context-label">
              Techniques ({detail.technique_count})
            </span>
            {tacticGroups.length > 0 ? (
              <div className="source-profile-tactics">
                {tacticGroups.map((group) => (
                  <span key={group.tactic} className="source-tactic-chip">
                    {formatTactic(splitTactics(group.tactic)[0] ?? group.tactic)}
                    <span className="source-tactic-count">{group.techniques.length}</span>
                  </span>
                ))}
              </div>
            ) : (
              <span className="source-profile-muted">No technique data loaded</span>
            )}
          </div>

          {detail.target_sectors.length > 0 ? (
            <div className="source-profile-section">
              <span className="actor-context-label">Target sectors</span>
              <div className="chip-list" style={{ marginTop: 4 }}>
                {detail.target_sectors.map((s) => (
                  <span className="technique-chip" key={s}>{s}</span>
                ))}
              </div>
            </div>
          ) : null}

          {detail.target_countries.length > 0 ? (
            <div className="source-profile-section">
              <span className="actor-context-label">Target countries</span>
              <div className="chip-list" style={{ marginTop: 4 }}>
                {detail.target_countries.map((c) => (
                  <span className="technique-chip" key={c}>{c}</span>
                ))}
              </div>
            </div>
          ) : null}

          {!hasEnrichment && tacticGroups.length === 0 ? (
            <p className="source-profile-muted">No additional details available for this profile.</p>
          ) : null}
        </div>
      ) : null}
    </div>
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
  if (metric === "jaccard_weighted") return "Weighted Jaccard";
  if (metric === "tactic_weighted_jaccard") return "Tactic weighted";
  if (metric === "software_weighted_jaccard") return "Software weighted";
  return "Jaccard";
}
