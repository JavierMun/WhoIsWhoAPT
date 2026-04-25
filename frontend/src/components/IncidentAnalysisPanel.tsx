import { AlertCircle, Download, FileJson, Loader2, Radar, Table, Upload } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { analyzeIncident, getTechniques } from "../api/client";
import { downloadComparisonExport } from "../api/exportUtils";
import {
  formatTactic,
  techniqueLabel,
  techniqueLookupFromList,
  techniqueTitle,
  type TechniqueLookup
} from "../api/ttpProfileUtils";
import type { ActorComparisonResponse, SimilarityMetric, SoftwareSummary, TacticBreakdown, TechniqueListItem } from "../api/types";

const DEFAULT_TOP_N = 10;

type NavigatorTechnique = {
  techniqueID?: unknown;
  techniqueId?: unknown;
  technique_id?: unknown;
  enabled?: unknown;
};

type NavigatorLayer = {
  name?: unknown;
  description?: unknown;
  techniques?: unknown;
};

export function IncidentAnalysisPanel() {
  const [techniques, setTechniques] = useState<TechniqueListItem[]>([]);
  const [incidentName, setIncidentName] = useState("Observed Incident");
  const [description, setDescription] = useState("");
  const [techniqueInput, setTechniqueInput] = useState("");
  const [metric, setMetric] = useState<SimilarityMetric>("jaccard_weighted");
  const [topN, setTopN] = useState(DEFAULT_TOP_N);
  const [loading, setLoading] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<ActorComparisonResponse | null>(null);

  useEffect(() => {
    getTechniques()
      .then(setTechniques)
      .catch(() => {
        setTechniques([]);
      });
  }, []);

  const parsedTechniqueIds = parseTechniqueIds(techniqueInput);
  const techniqueLookup = useMemo(() => techniqueLookupFromList(techniques), [techniques]);

  async function handleAnalyze() {
    setError(null);
    setNotice(null);
    setAnalysis(null);

    if (parsedTechniqueIds.length === 0) {
      setError("Enter at least one ATT&CK technique ID.");
      return;
    }

    setLoading(true);
    try {
      setAnalysis(
        await analyzeIncident({
          incidentName: incidentName.trim() || "Observed Incident",
          description: description.trim() || undefined,
          techniqueIds: parsedTechniqueIds,
          metric,
          topN
        })
      );
    } catch (apiError) {
      setError(apiError instanceof Error ? apiError.message : "Unable to analyze incident");
    } finally {
      setLoading(false);
    }
  }

  async function handleNavigatorImport(file: File | undefined) {
    if (!file) {
      return;
    }

    setError(null);
    setNotice(null);

    try {
      const layer = JSON.parse(await file.text()) as NavigatorLayer;
      const techniqueIds = extractNavigatorTechniqueIds(layer);
      if (techniqueIds.length === 0) {
        setError("Navigator layer did not contain enabled ATT&CK technique IDs.");
        return;
      }

      setTechniqueInput(mergeTechniqueInput(techniqueInput, techniqueIds));
      if (typeof layer.name === "string" && layer.name.trim()) {
        setIncidentName(layer.name.trim());
      }
      if (typeof layer.description === "string" && layer.description.trim()) {
        setDescription(layer.description.trim());
      }
      setNotice(`Imported ${techniqueIds.length} techniques from Navigator JSON.`);
    } catch (parseError) {
      setError(parseError instanceof Error ? parseError.message : "Unable to read Navigator layer");
    }
  }

  return (
    <section className="comparison-workspace incident-workspace" aria-labelledby="incident-title">
      <div className="workspace-header">
        <div>
          <p className="eyebrow">Incident Analysis</p>
          <h1 id="incident-title">Match observed TTPs to actors</h1>
        </div>
        <div className="source-pill">
          <Radar size={16} aria-hidden="true" />
          <span>{parsedTechniqueIds.length} techniques</span>
        </div>
      </div>

      <div className="incident-layout">
        <form
          className="control-panel incident-controls"
          onSubmit={(event) => {
            event.preventDefault();
            void handleAnalyze();
          }}
        >
          <label className="field-group" htmlFor="incident-name">
            <span>Incident name</span>
            <input
              id="incident-name"
              value={incidentName}
              onChange={(event) => {
                setIncidentName(event.target.value);
              }}
            />
          </label>

          <label className="field-group" htmlFor="incident-description">
            <span>Description</span>
            <textarea
              id="incident-description"
              value={description}
              onChange={(event) => {
                setDescription(event.target.value);
              }}
              rows={3}
              placeholder="Optional case notes"
            />
          </label>

          <label className="field-group" htmlFor="incident-techniques">
            <span>Observed techniques</span>
            <textarea
              id="incident-techniques"
              value={techniqueInput}
              onChange={(event) => {
                setTechniqueInput(event.target.value);
              }}
              rows={7}
              placeholder="T1059, T1105&#10;T1027"
            />
          </label>

          <label className="field-group" htmlFor="incident-navigator-import">
            <span>Import Navigator layer</span>
            <div className="file-input-row">
              <Upload size={17} aria-hidden="true" />
              <input
                id="incident-navigator-import"
                type="file"
                accept="application/json,.json"
                onChange={(event) => {
                  void handleNavigatorImport(event.target.files?.[0]);
                  event.target.value = "";
                }}
              />
            </div>
          </label>

          <div className="selected-actor incident-technique-summary">
            <p>{parsedTechniqueIds.length} normalized techniques</p>
            <span>
              {parsedTechniqueIds.length > 0
                ? parsedTechniqueIds
                    .slice(0, 10)
                    .map((techniqueId) => techniqueLabel(techniqueId, techniqueLookup))
                    .join(", ")
                : "Paste IDs or import a Navigator layer"}
            </span>
          </div>

          <div className="split-controls">
            <label className="field-group" htmlFor="incident-metric-select">
              <span>Metric</span>
              <select
                id="incident-metric-select"
                value={metric}
                onChange={(event) => {
                  setMetric(event.target.value as SimilarityMetric);
                }}
              >
                <option value="jaccard">Jaccard</option>
                <option value="jaccard_weighted">Weighted Jaccard</option>
                <option value="tactic_weighted_jaccard">Tactic weighted</option>
                <option value="software_weighted_jaccard">Software weighted</option>
              </select>
            </label>

            <label className="field-group" htmlFor="incident-top-n-input">
              <span>Results</span>
              <input
                id="incident-top-n-input"
                type="number"
                min={1}
                max={100}
                value={topN}
                onChange={(event) => {
                  const nextValue = Number(event.target.value);
                  setTopN(Number.isFinite(nextValue) ? Math.min(100, Math.max(1, nextValue)) : DEFAULT_TOP_N);
                }}
              />
            </label>
          </div>

          <button className="primary-action" type="submit" disabled={loading}>
            {loading ? <Loader2 className="spin" size={18} aria-hidden="true" /> : <Radar size={18} aria-hidden="true" />}
            <span>{loading ? "Analyzing" : "Analyze incident"}</span>
          </button>

          {notice ? <StatusMessage tone="neutral" message={notice} /> : null}
          {error ? <StatusMessage tone="error" message={error} /> : null}
        </form>

        <IncidentResults analysis={analysis} loading={loading} topN={topN} techniqueLookup={techniqueLookup} />
      </div>
    </section>
  );
}

function IncidentResults({
  analysis,
  loading,
  topN,
  techniqueLookup
}: {
  analysis: ActorComparisonResponse | null;
  loading: boolean;
  topN: number;
  techniqueLookup: TechniqueLookup;
}) {
  if (loading) {
    return (
      <section className="results-panel incident-results" aria-live="polite">
        <div className="empty-state">
          <Loader2 className="spin" size={22} aria-hidden="true" />
          <p>Analyzing observed TTPs</p>
        </div>
      </section>
    );
  }

  if (!analysis) {
    return (
      <section className="results-panel incident-results">
        <div className="empty-state">
          <Radar size={24} aria-hidden="true" />
          <p>Enter observed techniques to find similar actors.</p>
        </div>
      </section>
    );
  }

  const canExport = analysis.results.length > 0;

  return (
    <section className="results-panel incident-results" aria-live="polite">
      <div className="results-header">
        <div>
          <p className="panel-label">Incident</p>
          <h2>{analysis.input_name}</h2>
        </div>
        <div className="results-actions">
          <span className="metric-label">{metricLabel(analysis.metric)}</span>
          <button
            type="button"
            title={canExport ? "Export JSON" : "Run an analysis with results before exporting"}
            disabled={!canExport}
            onClick={() => downloadComparisonExport(analysis, "json", "mitre", topN, techniqueLookup)}
          >
            <FileJson size={16} aria-hidden="true" />
          </button>
          <button
            type="button"
            title={canExport ? "Export CSV" : "Run an analysis with results before exporting"}
            disabled={!canExport}
            onClick={() => downloadComparisonExport(analysis, "csv", "mitre", topN, techniqueLookup)}
          >
            <Table size={16} aria-hidden="true" />
          </button>
          <button
            type="button"
            title={canExport ? "Export Navigator layer" : "Run an analysis with results before exporting"}
            disabled={!canExport}
            onClick={() => downloadComparisonExport(analysis, "navigator", "mitre", topN, techniqueLookup)}
          >
            <Download size={16} aria-hidden="true" />
          </button>
        </div>
      </div>

      <ol className="result-list">
        {analysis.results.length === 0 ? (
          <li className="empty-result">No matching actors found. Load MITRE data or add more techniques.</li>
        ) : null}
        {analysis.results.map((result, index) => (
          <li className="result-row incident-result-row" key={result.matched_entity_id}>
            <div className="rank">{index + 1}</div>
            <div className="result-main">
              <div className="result-title-line">
                <h3>{result.matched_entity_name}</h3>
                <strong>{formatScore(result.score)}</strong>
              </div>
              <div className="result-meta">
                <span>{result.shared_techniques.length} shared techniques</span>
                <span>{result.unique_to_input.length} unmatched observed</span>
                <span>{result.unique_to_matched_entity.length} actor-only techniques</span>
              </div>

              <WhyMatched result={result} techniqueLookup={techniqueLookup} />
              <TacticBreakdownList items={result.tactic_breakdown} techniqueLookup={techniqueLookup} />
              <SoftwarePreview software={result.shared_software} />
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

function WhyMatched({
  result,
  techniqueLookup
}: {
  result: ActorComparisonResponse["results"][number];
  techniqueLookup: TechniqueLookup;
}) {
  const rareShared = result.rare_shared_techniques ?? [];
  return (
    <div className="why-match">
      <strong>Why this matched</strong>
      <p>
        Technique overlap score {formatScore(result.technique_score)}
        {result.software_score > 0 ? `, software overlap ${formatScore(result.software_score)}` : ""}.
      </p>
      <TechniqueLine
        label="Shared techniques"
        techniques={result.shared_techniques}
        emptyText="No shared techniques"
        techniqueLookup={techniqueLookup}
      />
      {rareShared.length > 0 ? (
        <TechniqueLine label="Rare shared techniques" techniques={rareShared} emptyText="" techniqueLookup={techniqueLookup} />
      ) : null}
    </div>
  );
}

function TechniqueLine({
  label,
  techniques,
  emptyText,
  techniqueLookup
}: {
  label: string;
  techniques: string[];
  emptyText: string;
  techniqueLookup: TechniqueLookup;
}) {
  const visible = techniques.slice(0, 12);
  const hiddenCount = techniques.length - visible.length;
  return (
    <p className="technique-preview">
      <strong>{label}</strong>{" "}
      {visible.length > 0
        ? visible.map((techniqueId, index) => (
            <span className="technique-label" key={techniqueId} title={techniqueTitle(techniqueId, techniqueLookup)}>
              {index > 0 ? ", " : ""}
              {techniqueLabel(techniqueId, techniqueLookup)}
            </span>
          ))
        : emptyText}
      {hiddenCount > 0 ? ` +${hiddenCount} more` : ""}
    </p>
  );
}

function SoftwarePreview({ software }: { software: SoftwareSummary[] }) {
  if (software.length === 0) {
    return null;
  }

  const visible = software.slice(0, 6).map((item) => item.name);
  const hiddenCount = software.length - visible.length;

  return (
    <p className="software-preview">
      <strong>Shared software</strong> {visible.join(", ")}
      {hiddenCount > 0 ? ` +${hiddenCount} more` : ""}
    </p>
  );
}

function TacticBreakdownList({ items, techniqueLookup }: { items: TacticBreakdown[]; techniqueLookup: TechniqueLookup }) {
  const visibleItems = items.filter((item) => item.union_technique_count > 0).slice(0, 5);
  if (visibleItems.length === 0) {
    return null;
  }

  return (
    <div className="tactic-breakdown" aria-label="Tactic breakdown">
      {visibleItems.map((item) => (
        <div className="tactic-row" key={item.tactic}>
          <div className="tactic-row-header">
            <strong>{formatTactic(item.tactic)}</strong>
            <span>{formatScore(item.score_contribution)}</span>
          </div>
          <div className="tactic-meter" aria-hidden="true">
            <span style={{ width: `${Math.round(item.score_contribution * 100)}%` }} />
          </div>
          <p>
            {item.shared_technique_count}/{item.union_technique_count} shared
            {item.shared_techniques.length > 0 ? ": " : ""}
            {item.shared_techniques.slice(0, 5).map((techniqueId, index) => (
              <span className="technique-label" key={techniqueId} title={techniqueTitle(techniqueId, techniqueLookup)}>
                {index > 0 ? ", " : ""}
                {techniqueLabel(techniqueId, techniqueLookup)}
              </span>
            ))}
          </p>
        </div>
      ))}
    </div>
  );
}

function StatusMessage({ tone, message }: { tone: "neutral" | "error"; message: string }) {
  return (
    <div className={`status-message ${tone}`}>
      {tone === "error" ? (
        <AlertCircle size={17} aria-hidden="true" />
      ) : (
        <Upload size={17} aria-hidden="true" />
      )}
      <span>{message}</span>
    </div>
  );
}

function parseTechniqueIds(value: string): string[] {
  return Array.from(new Set(value.toUpperCase().match(/T\d{4}(?:\.\d{3})?/g) ?? [])).sort((left, right) =>
    left.localeCompare(right)
  );
}

function extractNavigatorTechniqueIds(layer: NavigatorLayer): string[] {
  if (!Array.isArray(layer.techniques)) {
    throw new Error("Navigator layer must contain a techniques array.");
  }

  const techniqueIds = layer.techniques
    .map((item) => {
      const technique = item as NavigatorTechnique;
      if (technique.enabled === false) {
        return null;
      }
      return technique.techniqueID ?? technique.techniqueId ?? technique.technique_id;
    })
    .map((techniqueId) => (typeof techniqueId === "string" ? techniqueId.trim().toUpperCase() : null))
    .filter((techniqueId): techniqueId is string => techniqueId !== null && /^T\d{4}(?:\.\d{3})?$/.test(techniqueId));

  return Array.from(new Set(techniqueIds)).sort((left, right) => left.localeCompare(right));
}

function mergeTechniqueInput(currentInput: string, techniqueIds: string[]): string {
  return Array.from(new Set([...parseTechniqueIds(currentInput), ...techniqueIds]))
    .sort((left, right) => left.localeCompare(right))
    .join("\n");
}

function formatScore(score: number): string {
  return `${Math.round(score * 100)}%`;
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
