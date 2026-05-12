import { BarChart3, ChevronDown, ChevronUp, Download, FileJson, RefreshCw, Save, Table } from "lucide-react";
import { useEffect, useState } from "react";

import { getActorDetail, saveAnalysis } from "../api/client";
import { downloadComparisonExport } from "../api/exportUtils";
import { formatTactic, type TechniqueLookup } from "../api/ttpProfileUtils";
import type { ActorComparisonResponse, ActorDetail, SimilarityMetric } from "../api/types";
import { ComparisonGraphView } from "./ComparisonGraphView";
import { ComparisonHeatmapView } from "./ComparisonHeatmapView";
import { ComparisonRankingView } from "./ComparisonRankingView";

type ComparisonView = "ranking" | "heatmap" | "graph";

export function ComparisonResultTabs({
  comparison,
  topN,
  tacticScopeLabel,
  tactics,
  targetIds,
  actorAliases,
  canSave = true,
  onAnalysisSaved,
  onRerun,
  techniqueLookup
}: {
  comparison: ActorComparisonResponse;
  topN: number;
  comparisonScopeLabel: string;
  tacticScopeLabel: string;
  tactics?: string[];
  targetIds?: string[];
  actorAliases?: Record<string, string>;
  canSave?: boolean;
  onAnalysisSaved?: () => void;
  onRerun?: () => void;
  techniqueLookup: TechniqueLookup;
}) {
  const [activeView, setActiveView] = useState<ComparisonView>("ranking");
  const [savingAnalysis, setSavingAnalysis] = useState(false);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [inputDetail, setInputDetail] = useState<ActorDetail | null>(null);
  const [panelOpen, setPanelOpen] = useState(false);

  useEffect(() => {
    setInputDetail(null);
    setPanelOpen(false);
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
      setSaveMessage(`Saved ${saved.id.slice(0, 8)}`);
      onAnalysisSaved?.();
    } catch (apiError) {
      setSaveError(apiError instanceof Error ? apiError.message : "Unable to save analysis");
    } finally {
      setSavingAnalysis(false);
    }
  }

  const inputAlias = inputDetail?.aliases?.find((a) => a !== comparison.input_name);

  return (
    <section className="results-panel comparison-results-panel" aria-live="polite">

      {/* ── Compact summary bar ─────────────────────────────────── */}
      <div className="results-summary-bar">
        <div className="results-summary-source">
          <span className="results-summary-label">Source</span>
          <div className="results-summary-name-row">
            <strong>{comparison.input_name}</strong>
            {inputAlias ? <span className="results-summary-alias">{inputAlias}</span> : null}
            {inputDetail ? (
              <button
                type="button"
                className="summary-expand-btn"
                onClick={() => setPanelOpen((v) => !v)}
                aria-expanded={panelOpen}
                title="Show actor details"
              >
                {panelOpen ? <ChevronUp size={12} aria-hidden="true" /> : <ChevronDown size={12} aria-hidden="true" />}
              </button>
            ) : null}
          </div>
          {inputDetail ? (
            <div className="results-summary-tags">
              {inputDetail.motivation ? (
                <span className="results-summary-tag">◎ {inputDetail.motivation}</span>
              ) : null}
              <span className="results-summary-tag">⟨{inputDetail.technique_count}⟩ techniques</span>
            </div>
          ) : null}
        </div>

        <div className="results-summary-meta">
          <div className="results-summary-meta-item">
            <span className="results-summary-label">Metric</span>
            <span className="results-summary-value">{metricLabel(comparison.metric)}</span>
          </div>
          <div className="results-summary-meta-item">
            <span className="results-summary-label">Scope</span>
            <span className="results-summary-value">{tacticScopeLabel}</span>
          </div>
          <div className="results-summary-meta-item">
            <span className="results-summary-label">Compared</span>
            <span className="results-summary-value">{comparison.results.length} actors</span>
          </div>
        </div>

        <div className="results-actions">
          {onRerun ? (
            <button type="button" className="icon-action-btn" title="Re-run comparison" onClick={onRerun}>
              <RefreshCw size={15} aria-hidden="true" />
            </button>
          ) : null}
          {canSave ? (
            <button className="icon-action-btn" type="button" title={savingAnalysis ? "Saving…" : "Save analysis"} disabled={savingAnalysis} onClick={() => void handleSaveAnalysis()}>
              <Save size={15} aria-hidden="true" />
            </button>
          ) : null}
          <button type="button" title="Export JSON" onClick={() => downloadComparisonExport(comparison, "json", "mitre", topN, techniqueLookup)}>
            <FileJson size={14} aria-hidden="true" />
          </button>
          <button type="button" title="Export CSV" onClick={() => downloadComparisonExport(comparison, "csv", "mitre", topN, techniqueLookup)}>
            <Table size={14} aria-hidden="true" />
          </button>
          <button type="button" title="Export Navigator" onClick={() => downloadComparisonExport(comparison, "navigator", "mitre", topN, techniqueLookup)}>
            <Download size={14} aria-hidden="true" />
          </button>
        </div>
      </div>

      {/* ── Expanded actor profile panel ────────────────────────── */}
      {panelOpen && inputDetail ? (
        <ActorProfilePanel detail={inputDetail} techniqueLookup={techniqueLookup} />
      ) : null}

      {saveMessage ? <div className="analysis-save-status success">{saveMessage}</div> : null}
      {saveError ? <div className="analysis-save-status error">{saveError}</div> : null}

      {/* ── Tabs ────────────────────────────────────────────────── */}
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
            actorAliases={actorAliases}
          />
        ) : null}
        {activeView === "heatmap" ? <ComparisonHeatmapView comparison={comparison} /> : null}
        {activeView === "graph" ? <ComparisonGraphView comparison={comparison} /> : null}
      </div>
    </section>
  );
}

// ── Expanded actor profile panel ──────────────────────────────────────────

function ActorProfilePanel({ detail, techniqueLookup }: { detail: ActorDetail; techniqueLookup: TechniqueLookup }) {
  const techniqueGroups = detail.techniques
    .map((ref) => {
      const t = techniqueLookup.get(ref.technique_id);
      return { id: ref.technique_id, name: t?.name ?? "", tactic: t?.tactic ?? "" };
    })
    .filter((t) => t.name);

  return (
    <div className="actor-profile-panel">
      <div className="actor-profile-inner">
        {/* Left: details */}
        <div className="actor-profile-left">
          <div className="actor-profile-header">
            <h3>{detail.name}</h3>
            <span className="source-card-type-badge">ACTOR</span>
          </div>

          {detail.description ? (
            <p className="actor-profile-desc">{detail.description.slice(0, 280)}{detail.description.length > 280 ? "…" : ""}</p>
          ) : null}

          <div className="actor-profile-stats">
            {detail.motivation ? (
              <div className="actor-stat">
                <span className="actor-stat-label">Motivation</span>
                <span className="actor-stat-value">{detail.motivation}</span>
              </div>
            ) : null}
            <div className="actor-stat">
              <span className="actor-stat-label">Techniques</span>
              <span className="actor-stat-value">{detail.technique_count}</span>
            </div>
            <div className="actor-stat">
              <span className="actor-stat-label">Software</span>
              <span className="actor-stat-value">{detail.software_count}</span>
            </div>
          </div>

          {detail.target_sectors.length > 0 ? (
            <div className="actor-profile-section">
              <span className="actor-profile-section-label">Targeted Sectors</span>
              <div className="chip-list">
                {detail.target_sectors.map((s) => (
                  <span className="technique-chip" key={s}>{s}</span>
                ))}
              </div>
            </div>
          ) : null}

          {detail.target_countries.length > 0 ? (
            <div className="actor-profile-section">
              <span className="actor-profile-section-label">Targeted Regions</span>
              <div className="chip-list">
                {detail.target_countries.slice(0, 8).map((c) => (
                  <span className="technique-chip" key={c}>⊕ {c}</span>
                ))}
                {detail.target_countries.length > 8 ? (
                  <span
                    className="technique-chip unknown-chip"
                    title={detail.target_countries.slice(8).join(", ")}
                    style={{ cursor: "help" }}
                  >
                    +{detail.target_countries.length - 8} more
                  </span>
                ) : null}
              </div>
            </div>
          ) : null}

          {detail.software_used.length > 0 ? (
            <div className="actor-profile-section">
              <span className="actor-profile-section-label">Software ({detail.software_used.length})</span>
              <div className="chip-list">
                {detail.software_used.slice(0, 12).map((sw) => (
                  <span
                    className={`technique-chip ${sw.software_type === "malware" ? "chip-malware" : "chip-tool"}`}
                    key={sw.id}
                    title={sw.software_type}
                  >
                    {sw.name}
                  </span>
                ))}
                {detail.software_used.length > 12 ? (
                  <span
                    className="technique-chip unknown-chip"
                    title={detail.software_used.slice(12).map((s) => s.name).join(", ")}
                    style={{ cursor: "help" }}
                  >
                    +{detail.software_used.length - 12} more
                  </span>
                ) : null}
              </div>
            </div>
          ) : null}
        </div>

        {/* Right: techniques list */}
        <div className="actor-profile-right">
          <div className="actor-profile-section-label" style={{ marginBottom: 8 }}>
            Techniques ({detail.technique_count})
          </div>
          <ul className="actor-technique-list">
            {techniqueGroups.slice(0, 12).map((t) => (
              <li key={t.id} className="actor-technique-row">
                <span className="actor-technique-id">{t.id}</span>
                <span className="actor-technique-name">{t.name}</span>
                {t.tactic ? (
                  <span className="actor-technique-tactic">
                    {formatTactic(t.tactic.split(",")[0].trim())}
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

function TabButton({ active, label, onClick }: { active: boolean; label: string; onClick: () => void }) {
  return (
    <button className={active ? "active" : ""} type="button" role="tab" aria-selected={active} onClick={onClick}>
      {label === "Ranking" ? <BarChart3 size={14} aria-hidden="true" /> : null}
      {label === "Heatmap" ? <Table size={14} aria-hidden="true" /> : null}
      {label === "Graph" ? <BarChart3 size={14} aria-hidden="true" /> : null}
      <span>{label}</span>
    </button>
  );
}

function metricLabel(metric: SimilarityMetric): string {
  if (metric === "jaccard_weighted") return "Weighted Jaccard";
  if (metric === "tactic_weighted_jaccard") return "Tactic-w. Jaccard";
  if (metric === "software_weighted_jaccard") return "Software-w. Jaccard";
  if (metric === "holistic") return "Holistic";
  return "Jaccard";
}
