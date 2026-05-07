import { Grid3X3, RefreshCw } from "lucide-react";
import { useMemo, useState } from "react";

import { computeMatrix, getMatrixResult } from "../api/client";
import { clampScore } from "../api/comparisonViewUtils";
import type { MatrixResponse, SimilarityMetric } from "../api/types";

interface ActorPair {
  actorA: string;
  actorB: string;
  score: number;
}

function extractPairs(matrix: MatrixResponse): ActorPair[] {
  const pairs: ActorPair[] = [];
  const actors = matrix.actors;
  for (let i = 0; i < actors.length; i++) {
    for (let j = i + 1; j < actors.length; j++) {
      const score = clampScore(matrix.matrix[i]?.[j] ?? 0);
      if (score > 0) {
        pairs.push({ actorA: actors[i].name, actorB: actors[j].name, score });
      }
    }
  }
  return pairs.sort((a, b) => b.score - a.score);
}

export function ActorSimilarityPanel() {
  const [metric, setMetric] = useState<SimilarityMetric>("jaccard");
  const [threshold, setThreshold] = useState(20);
  const [matrix, setMatrix] = useState<MatrixResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingMode, setLoadingMode] = useState<"compute" | "retrieve">("compute");
  const [error, setError] = useState<string | null>(null);
  const [visibleCount, setVisibleCount] = useState(50);

  async function handleCompute() {
    setLoading(true);
    setLoadingMode("compute");
    setError(null);
    try {
      setMatrix(await computeMatrix(metric));
      setVisibleCount(50);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to compute matrix");
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
      setVisibleCount(50);
    } catch (err) {
      setError(err instanceof Error ? err.message : "No matrix available — compute one first");
    } finally {
      setLoading(false);
    }
  }

  const allPairs = useMemo(() => (matrix ? extractPairs(matrix) : []), [matrix]);

  const filteredPairs = useMemo(
    () => allPairs.filter((p) => Math.round(p.score * 100) >= threshold),
    [allPairs, threshold]
  );

  const topScore = filteredPairs[0]?.score ?? 1;

  return (
    <section className="comparison-workspace similarity-search-workspace" aria-labelledby="sim-search-title">
      <div className="workspace-header">
        <div>
          <p className="eyebrow">Explore · All-vs-All</p>
          <h1 id="sim-search-title">Actor pair similarity ranking</h1>
          <p className="scope-summary">
            All actor pairs ranked by TTP overlap. Uses the same matrix as the heatmap.
          </p>
        </div>
        {matrix ? (
          <div className="source-pill">
            <Grid3X3 size={14} aria-hidden="true" />
            <span>{matrix.metadata.actor_count} actors · {allPairs.length.toLocaleString()} pairs</span>
          </div>
        ) : null}
      </div>

      <div className="comparison-layout">
        {/* Controls */}
        <div className="control-panel">
          <div className="field-group">
            <span>Metric</span>
            <select value={metric} onChange={(e) => setMetric(e.target.value as SimilarityMetric)}>
              <option value="jaccard">Jaccard</option>
              <option value="jaccard_weighted">Weighted Jaccard</option>
              <option value="tactic_weighted_jaccard">Tactic weighted</option>
              <option value="software_weighted_jaccard">Software weighted</option>
              <option value="holistic">Holistic</option>
            </select>
          </div>

          <button className="primary-action" type="button" disabled={loading} onClick={() => void handleCompute()}>
            {loading && loadingMode === "compute" ? (
              <><RefreshCw size={15} className="spin" aria-hidden="true" /><span>Computing…</span></>
            ) : (
              <><Grid3X3 size={15} aria-hidden="true" /><span>Compute all-vs-all</span></>
            )}
          </button>

          <button className="secondary-action" type="button" disabled={loading} onClick={() => void handleRetrieve()}>
            {loading && loadingMode === "retrieve" ? (
              <><RefreshCw size={15} className="spin" aria-hidden="true" /><span>Loading…</span></>
            ) : (
              <><RefreshCw size={15} aria-hidden="true" /><span>Use existing matrix</span></>
            )}
          </button>

          {error ? (
            <p style={{ margin: 0, color: "var(--danger)", fontSize: "0.82rem" }}>{error}</p>
          ) : null}

          {matrix ? (
            <>
              <div className="field-group" style={{ marginTop: 8 }}>
                <span>
                  Min. similarity:&nbsp;
                  <strong style={{ color: "var(--accent-text)", fontFamily: "var(--mono)" }}>
                    {threshold}%
                  </strong>
                </span>
                <input
                  type="range"
                  min={0}
                  max={80}
                  step={5}
                  value={threshold}
                  onChange={(e) => { setThreshold(Number(e.target.value)); setVisibleCount(50); }}
                  style={{ width: "100%", accentColor: "var(--accent)" }}
                />
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.63rem", color: "var(--text-4)", fontFamily: "var(--mono)" }}>
                  <span>0%</span><span>20%</span><span>40%</span><span>60%</span><span>80%</span>
                </div>
              </div>

              <div className="sim-result-summary">
                <span className="sim-result-count">{filteredPairs.length.toLocaleString()}</span>
                <span className="sim-result-label">pairs ≥ {threshold}% similarity</span>
                <span className="sim-result-total">of {allPairs.length.toLocaleString()} total pairs</span>
              </div>
            </>
          ) : null}
        </div>

        {/* Results */}
        <div className="results-panel sim-results-panel">
          {!matrix ? (
            <div className="empty-state">
              <Grid3X3 size={28} aria-hidden="true" />
              <p>Compute or load a matrix to see all actor pairs ranked by similarity.</p>
            </div>
          ) : filteredPairs.length === 0 ? (
            <div className="empty-state">
              <p>No pairs above {threshold}% similarity. Lower the threshold.</p>
            </div>
          ) : (
            <>
              <ol className="sim-result-list">
                {filteredPairs.slice(0, visibleCount).map((pair, index) => {
                  const pct = Math.round(pair.score * 100);
                  const barWidth = Math.round((pair.score / topScore) * 100);
                  return (
                    <li key={`${pair.actorA}-${pair.actorB}`} className="sim-result-row">
                      <span className="sim-rank">{String(index + 1).padStart(2, "0")}</span>
                      <div className="sim-result-main">
                        <div className="sim-pair-names">
                          <span className="sim-result-name">{pair.actorA}</span>
                          <span className="sim-pair-sep">↔</span>
                          <span className="sim-result-name">{pair.actorB}</span>
                        </div>
                        <div className="sim-bar-track" title={`${pct}%`}>
                          <div className="sim-bar-fill" style={{ width: `${barWidth}%` }} />
                        </div>
                      </div>
                      <span className="sim-score">
                        {pct}<span style={{ fontSize: "0.7rem" }}>%</span>
                      </span>
                    </li>
                  );
                })}
              </ol>
              {filteredPairs.length > visibleCount ? (
                <div style={{ padding: "12px 16px", textAlign: "center" }}>
                  <button
                    type="button"
                    className="secondary-action"
                    onClick={() => setVisibleCount((n) => n + 50)}
                  >
                    Show more ({filteredPairs.length - visibleCount} remaining)
                  </button>
                </div>
              ) : null}
            </>
          )}
        </div>
      </div>
    </section>
  );
}
