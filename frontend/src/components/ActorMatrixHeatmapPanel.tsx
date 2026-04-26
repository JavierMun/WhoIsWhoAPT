import { AlertCircle, Grid3X3, Loader2, RefreshCw, Search } from "lucide-react";
import { useMemo, useState } from "react";

import { computeMatrix, getMatrixResult } from "../api/client";
import { clampScore, comparisonHeatColor } from "../api/comparisonViewUtils";
import type { MatrixResponse, SimilarityMetric } from "../api/types";

const DEFAULT_VISIBLE_ACTORS = 30;
const MAX_VISIBLE_ACTORS = 80;

export function ActorMatrixHeatmapPanel() {
  const [metric, setMetric] = useState<SimilarityMetric>("jaccard");
  const [actorQuery, setActorQuery] = useState("");
  const [visibleLimit, setVisibleLimit] = useState(DEFAULT_VISIBLE_ACTORS);
  const [matrix, setMatrix] = useState<MatrixResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingMode, setLoadingMode] = useState<"compute" | "retrieve">("compute");
  const [error, setError] = useState<string | null>(null);

  async function handleCompute() {
    setLoading(true);
    setLoadingMode("compute");
    setError(null);

    try {
      setMatrix(await computeMatrix(metric));
    } catch (apiError) {
      setError(apiError instanceof Error ? apiError.message : "Unable to compute matrix");
    } finally {
      setLoading(false);
    }
  }

  async function handleRetrieve() {
    setLoading(true);
    setLoadingMode("retrieve");
    setError(null);

    try {
      setMatrix(await getMatrixResult());
    } catch (apiError) {
      setError(apiError instanceof Error ? apiError.message : "Unable to retrieve matrix");
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="comparison-workspace matrix-workspace" aria-labelledby="matrix-title">
      <div className="workspace-header">
        <div>
          <p className="eyebrow">Similarity Matrix</p>
          <h1 id="matrix-title">Actor heatmap</h1>
        </div>
        <div className="source-pill">
          <Grid3X3 size={16} aria-hidden="true" />
          <span>{matrix ? `${matrix.metadata.actor_count} actors` : "Matrix"}</span>
        </div>
      </div>

      <div className="matrix-layout">
        <form
          className="control-panel matrix-controls"
          onSubmit={(event) => {
            event.preventDefault();
            void handleCompute();
          }}
        >
          <label className="field-group" htmlFor="matrix-metric-select">
            <span>Metric</span>
            <select
              id="matrix-metric-select"
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

          <label className="field-group" htmlFor="matrix-actor-filter">
            <span>Filter actors</span>
            <div className="search-field">
              <Search size={17} aria-hidden="true" />
              <input
                id="matrix-actor-filter"
                type="search"
                value={actorQuery}
                onChange={(event) => {
                  setActorQuery(event.target.value);
                }}
                placeholder="APT, group, alias"
              />
            </div>
          </label>

          <label className="field-group" htmlFor="matrix-visible-limit">
            <span>Top actors</span>
            <input
              id="matrix-visible-limit"
              type="number"
              min={1}
              max={MAX_VISIBLE_ACTORS}
              value={visibleLimit}
              onChange={(event) => {
                const nextValue = Number(event.target.value);
                setVisibleLimit(
                  Number.isFinite(nextValue)
                    ? Math.min(MAX_VISIBLE_ACTORS, Math.max(1, nextValue))
                    : DEFAULT_VISIBLE_ACTORS
                );
              }}
            />
          </label>

          <button className="primary-action" type="submit" disabled={loading}>
            {loading && loadingMode === "compute" ? (
              <Loader2 className="spin" size={18} aria-hidden="true" />
            ) : (
              <Grid3X3 size={18} aria-hidden="true" />
            )}
            <span>{loading && loadingMode === "compute" ? "Computing" : "Compute matrix"}</span>
          </button>

          <button className="secondary-action" type="button" disabled={loading} onClick={() => void handleRetrieve()}>
            {loading && loadingMode === "retrieve" ? (
              <Loader2 className="spin" size={18} aria-hidden="true" />
            ) : (
              <RefreshCw size={18} aria-hidden="true" />
            )}
            <span>{loading && loadingMode === "retrieve" ? "Retrieving" : "Retrieve latest"}</span>
          </button>

          <HeatmapLegend />
          {error ? <StatusMessage tone="error" message={error} /> : null}
        </form>

        <HeatmapPanel matrix={matrix} actorQuery={actorQuery} visibleLimit={visibleLimit} loading={loading} />
      </div>
    </section>
  );
}

function HeatmapPanel({
  matrix,
  actorQuery,
  visibleLimit,
  loading
}: {
  matrix: MatrixResponse | null;
  actorQuery: string;
  visibleLimit: number;
  loading: boolean;
}) {
  const visibleIndexes = useVisibleActorIndexes(matrix, actorQuery, visibleLimit);

  if (loading) {
    return (
      <section className="results-panel heatmap-panel" aria-live="polite">
        <div className="empty-state">
          <Loader2 className="spin" size={22} aria-hidden="true" />
          <p>Loading matrix</p>
        </div>
      </section>
    );
  }

  if (!matrix) {
    return (
      <section className="results-panel heatmap-panel">
        <div className="empty-state">
          <Grid3X3 size={24} aria-hidden="true" />
          <p>Compute or retrieve a matrix.</p>
        </div>
      </section>
    );
  }

  if (matrix.actors.length === 0) {
    return (
      <section className="results-panel heatmap-panel">
        <div className="empty-state">
          <Grid3X3 size={24} aria-hidden="true" />
          <p>No actors available in the active source.</p>
        </div>
      </section>
    );
  }

  if (visibleIndexes.length === 0) {
    return (
      <section className="results-panel heatmap-panel">
        <HeatmapHeader matrix={matrix} visibleCount={0} capped={false} />
        <div className="empty-state compact-empty">
          <Search size={24} aria-hidden="true" />
          <p>No actors match the filter.</p>
        </div>
      </section>
    );
  }

  const capped = visibleIndexes.length < matrix.actors.length;
  const showCellText = visibleIndexes.length <= 16;

  return (
    <section className="results-panel heatmap-panel" aria-live="polite">
      <HeatmapHeader matrix={matrix} visibleCount={visibleIndexes.length} capped={capped} />
      <div className="heatmap-scroll">
        <table className="heatmap-table" aria-label="Actor similarity heatmap">
          <thead>
            <tr>
              <th className="corner-cell" scope="col">
                Actor
              </th>
              {visibleIndexes.map((columnIndex) => {
                const actor = matrix.actors[columnIndex];
                return (
                  <th className="column-actor" key={actor.id} scope="col" title={actor.name}>
                    <span>{actor.name}</span>
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {visibleIndexes.map((rowIndex) => {
              const rowActor = matrix.actors[rowIndex];
              return (
                <tr key={rowActor.id}>
                  <th className="row-actor" scope="row" title={rowActor.name}>
                    {rowActor.name}
                  </th>
                  {visibleIndexes.map((columnIndex) => {
                    const columnActor = matrix.actors[columnIndex];
                    const value = clampScore(matrix.matrix[rowIndex]?.[columnIndex] ?? 0);
                    return (
                      <td
                        className="heatmap-cell"
                        key={columnActor.id}
                        style={{ backgroundColor: comparisonHeatColor(value), color: value >= 0.62 ? "#ffffff" : "#172026" }}
                        title={`${rowActor.name} to ${columnActor.name}: ${formatScore(value)} (${value.toFixed(4)})`}
                      >
                        {showCellText ? formatScore(value) : ""}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function HeatmapHeader({
  matrix,
  visibleCount,
  capped
}: {
  matrix: MatrixResponse;
  visibleCount: number;
  capped: boolean;
}) {
  return (
    <div className="results-header heatmap-header">
      <div>
        <p className="panel-label">Generated {formatDate(matrix.metadata.generated_at)}</p>
        <h2>
          {visibleCount}/{matrix.metadata.actor_count} actors
        </h2>
      </div>
      <div className="results-actions">
        {capped ? <span className="matrix-note">Limited view</span> : null}
        <span className="metric-label">{metricLabel(matrix.metadata.metric)}</span>
      </div>
    </div>
  );
}

function HeatmapLegend() {
  return (
    <div className="heatmap-legend" aria-label="Similarity color legend">
      <div className="mini-header">
        <strong>Legend</strong>
        <span>0-100%</span>
      </div>
      <div className="legend-ramp" aria-hidden="true" />
      <div className="legend-labels">
        <span>Low</span>
        <span>Medium</span>
        <span>High</span>
      </div>
    </div>
  );
}

function StatusMessage({ tone, message }: { tone: "error"; message: string }) {
  return (
    <div className={`status-message ${tone}`}>
      <AlertCircle size={17} aria-hidden="true" />
      <span>{message}</span>
    </div>
  );
}

function useVisibleActorIndexes(matrix: MatrixResponse | null, actorQuery: string, visibleLimit: number): number[] {
  return useMemo(() => {
    if (!matrix) {
      return [];
    }

    const normalizedQuery = actorQuery.trim().toLowerCase();
    const actorScores = matrix.actors
      .map((actor, index) => {
        const row = matrix.matrix[index] ?? [];
        const comparableValues = row.filter((_, columnIndex) => columnIndex !== index);
        const averageSimilarity =
          comparableValues.length > 0
            ? comparableValues.reduce((total, value) => total + clampScore(value), 0) / comparableValues.length
            : 0;
        return { actor, index, averageSimilarity };
      })
      .filter(({ actor }) => !normalizedQuery || actor.name.toLowerCase().includes(normalizedQuery));

    return actorScores
      .sort((left, right) => right.averageSimilarity - left.averageSimilarity || left.actor.name.localeCompare(right.actor.name))
      .slice(0, visibleLimit)
      .map((item) => item.index);
  }, [actorQuery, matrix, visibleLimit]);
}

function formatScore(score: number): string {
  return `${Math.round(clampScore(score) * 100)}%`;
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

function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}
