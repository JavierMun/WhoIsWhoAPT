import { AlertCircle, Download, FileJson, Loader2, Plus, Save, Search, Table, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { compareCustomSet, createCustomSet, getCustomSets, getTechniques } from "../api/client";
import { downloadComparisonExport } from "../api/exportUtils";
import {
  formatTactic,
  techniqueLabel,
  techniqueLookupFromList,
  techniqueTitle,
  type TechniqueLookup
} from "../api/ttpProfileUtils";
import type {
  ActorComparisonResponse,
  CustomTTPSet,
  SimilarityMetric,
  SoftwareSummary,
  TacticBreakdown,
  TechniqueListItem
} from "../api/types";

const DEFAULT_TOP_N = 10;

type NavigatorTechnique = {
  techniqueID?: unknown;
  techniqueId?: unknown;
  technique_id?: unknown;
  enabled?: unknown;
};

type NavigatorLayer = {
  name?: unknown;
  techniques?: unknown;
  domain?: unknown;
};

export function CustomTTPSetPanel() {
  const [techniques, setTechniques] = useState<TechniqueListItem[]>([]);
  const [customSets, setCustomSets] = useState<CustomTTPSet[]>([]);
  const [selectedTechniqueIds, setSelectedTechniqueIds] = useState<string[]>([]);
  const [techniqueQuery, setTechniqueQuery] = useState("");
  const [setName, setSetName] = useState("Custom TTP Set");
  const [selectedCustomSetId, setSelectedCustomSetId] = useState("");
  const [metric, setMetric] = useState<SimilarityMetric>("jaccard");
  const [topN, setTopN] = useState(DEFAULT_TOP_N);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [comparing, setComparing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [comparison, setComparison] = useState<ActorComparisonResponse | null>(null);

  useEffect(() => {
    Promise.all([getTechniques(), getCustomSets()])
      .then(([techniqueItems, customSetItems]) => {
        setTechniques(techniqueItems);
        setCustomSets(customSetItems);
        setSelectedCustomSetId(customSetItems[0]?.id ?? "");
      })
      .catch((apiError: unknown) => {
        setError(apiError instanceof Error ? apiError.message : "Unable to load custom set data");
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  const validTechniqueIds = useMemo(() => new Set(techniques.map((technique) => technique.technique_id)), [techniques]);
  const techniqueLookup = useMemo(() => techniqueLookupFromList(techniques), [techniques]);
  const selectedTechniques = selectedTechniqueIds
    .map((techniqueId) => techniques.find((technique) => technique.technique_id === techniqueId))
    .filter((technique): technique is TechniqueListItem => Boolean(technique));

  const filteredTechniques = useMemo(() => {
    const normalizedQuery = techniqueQuery.trim().toLowerCase();
    const pool = techniques.filter((technique) => !selectedTechniqueIds.includes(technique.technique_id));
    if (!normalizedQuery) {
      return pool.slice(0, 80);
    }

    return pool
      .filter((technique) => {
        return (
          technique.technique_id.toLowerCase().includes(normalizedQuery) ||
          technique.name.toLowerCase().includes(normalizedQuery) ||
          technique.tactic.toLowerCase().includes(normalizedQuery)
        );
      })
      .slice(0, 80);
  }, [selectedTechniqueIds, techniqueQuery, techniques]);

  async function handleSave() {
    setError(null);
    setNotice(null);

    if (selectedTechniqueIds.length === 0) {
      setError("Select at least one technique before saving.");
      return;
    }

    setSaving(true);
    try {
      const savedSet = await createCustomSet(setName.trim() || "Custom TTP Set", selectedTechniqueIds);
      const nextSets = await getCustomSets();
      setCustomSets(nextSets);
      setSelectedCustomSetId(savedSet.id);
      setNotice(`Saved ${savedSet.name}.`);
    } catch (apiError) {
      setError(apiError instanceof Error ? apiError.message : "Unable to save custom set");
    } finally {
      setSaving(false);
    }
  }

  async function handleCompareInline() {
    setError(null);
    setNotice(null);
    setComparison(null);

    if (selectedTechniqueIds.length === 0) {
      setError("Select or import at least one technique before comparing.");
      return;
    }

    setComparing(true);
    try {
      setComparison(
        await compareCustomSet({
          name: setName.trim() || "Inline TTP Set",
          techniqueIds: selectedTechniqueIds,
          metric,
          topN
        })
      );
    } catch (apiError) {
      setError(apiError instanceof Error ? apiError.message : "Unable to compare custom set");
    } finally {
      setComparing(false);
    }
  }

  async function handleCompareSaved() {
    setError(null);
    setNotice(null);
    setComparison(null);

    if (!selectedCustomSetId) {
      setError("Save or select a custom set before comparing.");
      return;
    }

    setComparing(true);
    try {
      setComparison(await compareCustomSet({ customSetId: selectedCustomSetId, metric, topN }));
    } catch (apiError) {
      setError(apiError instanceof Error ? apiError.message : "Unable to compare saved set");
    } finally {
      setComparing(false);
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
      const importedIds = extractNavigatorTechniqueIds(layer);
      const validIds = importedIds.filter((techniqueId) => validTechniqueIds.has(techniqueId));
      const invalidIds = importedIds.filter((techniqueId) => !validTechniqueIds.has(techniqueId));
      if (validIds.length === 0) {
        setError("Navigator layer did not contain techniques available in the loaded dataset.");
        return;
      }

      setSelectedTechniqueIds((currentIds) => sortedTechniqueIds([...currentIds, ...validIds]));
      if (typeof layer.name === "string" && layer.name.trim()) {
        setSetName(layer.name.trim());
      }
      setNotice(
        invalidIds.length > 0
          ? `Imported ${validIds.length} techniques. Ignored ${invalidIds.length} unknown IDs.`
          : `Imported ${validIds.length} techniques.`
      );
    } catch (parseError) {
      setError(parseError instanceof Error ? parseError.message : "Unable to read Navigator layer");
    }
  }

  return (
    <section className="comparison-workspace custom-workspace" aria-labelledby="custom-title">
      <div className="workspace-header">
        <div>
          <p className="eyebrow">Custom TTP Sets</p>
          <h1 id="custom-title">Build and compare a TTP profile</h1>
        </div>
        <div className="source-pill">
          <FileJson size={16} aria-hidden="true" />
          <span>Navigator JSON</span>
        </div>
      </div>

      <div className="custom-layout">
        <form
          className="control-panel"
          onSubmit={(event) => {
            event.preventDefault();
            void handleCompareInline();
          }}
        >
          <label className="field-group" htmlFor="custom-set-name">
            <span>Name</span>
            <input
              id="custom-set-name"
              value={setName}
              onChange={(event) => {
                setSetName(event.target.value);
              }}
            />
          </label>

          <label className="field-group" htmlFor="navigator-import">
            <span>Import Navigator layer</span>
            <input
              id="navigator-import"
              type="file"
              accept="application/json,.json"
              onChange={(event) => {
                void handleNavigatorImport(event.target.files?.[0]);
                event.target.value = "";
              }}
            />
          </label>

          <label className="field-group" htmlFor="technique-search">
            <span>Search techniques</span>
            <div className="search-field">
              <Search size={17} aria-hidden="true" />
              <input
                id="technique-search"
                type="search"
                value={techniqueQuery}
                onChange={(event) => {
                  setTechniqueQuery(event.target.value);
                }}
                placeholder="T1059, PowerShell, tactic"
              />
            </div>
          </label>

          <div className="technique-picker" aria-label="Technique search results">
            {filteredTechniques.map((technique) => (
              <button
                className="technique-option"
                key={technique.technique_id}
                type="button"
                onClick={() => {
                  setSelectedTechniqueIds((currentIds) => sortedTechniqueIds([...currentIds, technique.technique_id]));
                }}
              >
                <span>{techniqueLabel(technique.technique_id, techniqueLookup)}</span>
                <small>{technique.name}</small>
              </button>
            ))}
            {!loading && filteredTechniques.length === 0 ? <p className="muted">No matching techniques</p> : null}
          </div>

          <div className="selected-techniques">
            <div className="mini-header">
              <strong>{selectedTechniqueIds.length} selected</strong>
              <button
                type="button"
                onClick={() => {
                  setSelectedTechniqueIds([]);
                }}
              >
                Clear
              </button>
            </div>
            <div className="chip-list">
              {selectedTechniques.map((technique) => (
                <button
                  className="technique-chip"
                  key={technique.technique_id}
                  type="button"
                  onClick={() => {
                    setSelectedTechniqueIds((currentIds) =>
                      currentIds.filter((techniqueId) => techniqueId !== technique.technique_id)
                    );
                  }}
                  title={techniqueTitle(technique.technique_id, techniqueLookup)}
                >
                  <span>{techniqueLabel(technique.technique_id, techniqueLookup)}</span>
                  <X size={14} aria-hidden="true" />
                </button>
              ))}
            </div>
          </div>

          <div className="split-controls">
            <label className="field-group" htmlFor="custom-metric-select">
              <span>Metric</span>
              <select
                id="custom-metric-select"
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

            <label className="field-group" htmlFor="custom-top-n-input">
              <span>Results</span>
              <input
                id="custom-top-n-input"
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

          <div className="action-row">
            <button className="secondary-action" type="button" disabled={saving} onClick={() => void handleSave()}>
              {saving ? <Loader2 className="spin" size={17} aria-hidden="true" /> : <Save size={17} aria-hidden="true" />}
              <span>{saving ? "Saving" : "Save"}</span>
            </button>
            <button className="primary-action" type="submit" disabled={comparing}>
              {comparing ? <Loader2 className="spin" size={17} aria-hidden="true" /> : <Plus size={17} aria-hidden="true" />}
              <span>Compare inline</span>
            </button>
          </div>

          {loading ? <StatusMessage tone="neutral" message="Loading techniques" /> : null}
          {notice ? <StatusMessage tone="neutral" message={notice} /> : null}
          {error ? <StatusMessage tone="error" message={error} /> : null}
        </form>

        <section className="control-panel saved-panel" aria-label="Saved custom sets">
          <div className="mini-header">
            <strong>Saved sets</strong>
            <span>{customSets.length}</span>
          </div>
          <label className="field-group" htmlFor="saved-set-select">
            <span>Custom set</span>
            <select
              id="saved-set-select"
              value={selectedCustomSetId}
              disabled={customSets.length === 0}
              onChange={(event) => {
                setSelectedCustomSetId(event.target.value);
              }}
            >
              {customSets.map((customSet) => (
                <option key={customSet.id} value={customSet.id}>
                  {customSet.name} ({customSet.technique_ids.length})
                </option>
              ))}
            </select>
          </label>
          <button className="primary-action" type="button" disabled={!selectedCustomSetId || comparing} onClick={() => void handleCompareSaved()}>
            {comparing ? <Loader2 className="spin" size={17} aria-hidden="true" /> : <Plus size={17} aria-hidden="true" />}
            <span>Compare saved</span>
          </button>
        </section>

        <CustomComparisonResults comparison={comparison} loading={comparing} topN={topN} techniqueLookup={techniqueLookup} />
      </div>
    </section>
  );
}

function CustomComparisonResults({
  comparison,
  loading,
  topN,
  techniqueLookup
}: {
  comparison: ActorComparisonResponse | null;
  loading: boolean;
  topN: number;
  techniqueLookup: TechniqueLookup;
}) {
  if (loading) {
    return (
      <section className="results-panel custom-results" aria-live="polite">
        <div className="empty-state">
          <Loader2 className="spin" size={22} aria-hidden="true" />
          <p>Comparing custom set</p>
        </div>
      </section>
    );
  }

  if (!comparison) {
    return (
      <section className="results-panel custom-results">
        <div className="empty-state">
          <FileJson size={24} aria-hidden="true" />
          <p>Create, import, or select a custom set to compare.</p>
        </div>
      </section>
    );
  }

  const canExport = comparison.results.length > 0;

  return (
    <section className="results-panel custom-results" aria-live="polite">
      <div className="results-header">
        <div>
          <p className="panel-label">Custom input</p>
          <h2>{comparison.input_name}</h2>
        </div>
        <div className="results-actions">
          <span className="metric-label">{metricLabel(comparison.metric)}</span>
          <button
            type="button"
            title={canExport ? "Export JSON" : "Run a comparison with results before exporting"}
            disabled={!canExport}
            onClick={() => downloadComparisonExport(comparison, "json", "mitre", topN, techniqueLookup)}
          >
            <FileJson size={16} aria-hidden="true" />
          </button>
          <button
            type="button"
            title={canExport ? "Export CSV" : "Run a comparison with results before exporting"}
            disabled={!canExport}
            onClick={() => downloadComparisonExport(comparison, "csv", "mitre", topN, techniqueLookup)}
          >
            <Table size={16} aria-hidden="true" />
          </button>
          <button
            type="button"
            title={canExport ? "Export Navigator layer" : "Run a comparison with results before exporting"}
            disabled={!canExport}
            onClick={() => downloadComparisonExport(comparison, "navigator", "mitre", topN, techniqueLookup)}
          >
            <Download size={16} aria-hidden="true" />
          </button>
        </div>
      </div>
      <ol className="result-list">
        {comparison.results.length === 0 ? (
          <li className="empty-result">No comparable actors found. Load MITRE data before comparing custom sets.</li>
        ) : null}
        {comparison.results.map((result, index) => (
          <li className="result-row" key={result.matched_entity_id}>
            <div className="rank">{index + 1}</div>
            <div className="result-main">
              <div className="result-title-line">
                <h3>{result.matched_entity_name}</h3>
                <strong>{Math.round(result.score * 100)}%</strong>
              </div>
              <div className="result-meta">
                <span>{result.shared_techniques.length} shared techniques</span>
                <span>{result.unique_to_input.length} unmatched input</span>
              </div>
              <p className="technique-preview">
                {result.shared_techniques.length > 0
                  ? result.shared_techniques.slice(0, 8).map((techniqueId, itemIndex) => (
                      <span className="technique-label" key={techniqueId} title={techniqueTitle(techniqueId, techniqueLookup)}>
                        {itemIndex > 0 ? ", " : ""}
                        {techniqueLabel(techniqueId, techniqueLookup)}
                      </span>
                    ))
                  : "No shared techniques"}
              </p>
              <SoftwarePreview software={result.shared_software} />
              <TacticBreakdownList items={result.tactic_breakdown} techniqueLookup={techniqueLookup} />
            </div>
          </li>
        ))}
      </ol>
    </section>
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
  const visibleItems = items.filter((item) => item.union_technique_count > 0).slice(0, 4);
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
            {item.shared_techniques.slice(0, 4).map((techniqueId, index) => (
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
        <Loader2 className="spin" size={17} aria-hidden="true" />
      )}
      <span>{message}</span>
    </div>
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

  return sortedTechniqueIds(techniqueIds);
}

function sortedTechniqueIds(techniqueIds: string[]): string[] {
  return Array.from(new Set(techniqueIds)).sort((left, right) => left.localeCompare(right));
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
