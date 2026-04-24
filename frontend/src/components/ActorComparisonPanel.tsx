import { AlertCircle, BarChart3, Loader2, Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { compareActor, getActors } from "../api/client";
import type { ActorComparisonResponse, ActorListItem, SimilarityMetric } from "../api/types";

const DEFAULT_TOP_N = 10;

export function ActorComparisonPanel() {
  const [actors, setActors] = useState<ActorListItem[]>([]);
  const [actorQuery, setActorQuery] = useState("");
  const [selectedActorId, setSelectedActorId] = useState("");
  const [metric, setMetric] = useState<SimilarityMetric>("jaccard");
  const [topN, setTopN] = useState(DEFAULT_TOP_N);
  const [actorsLoading, setActorsLoading] = useState(true);
  const [compareLoading, setCompareLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [comparison, setComparison] = useState<ActorComparisonResponse | null>(null);

  useEffect(() => {
    getActors()
      .then((items) => {
        setActors(items);
        setSelectedActorId(items[0]?.id ?? "");
      })
      .catch((apiError: unknown) => {
        setError(apiError instanceof Error ? apiError.message : "Unable to load actors");
      })
      .finally(() => {
        setActorsLoading(false);
      });
  }, []);

  const filteredActors = useMemo(() => {
    const normalizedQuery = actorQuery.trim().toLowerCase();
    if (!normalizedQuery) {
      return actors;
    }

    return actors.filter((actor) => {
      const aliases = actor.aliases.join(" ").toLowerCase();
      return actor.name.toLowerCase().includes(normalizedQuery) || aliases.includes(normalizedQuery);
    });
  }, [actorQuery, actors]);

  const effectiveSelectedActorId = filteredActors.some((actor) => actor.id === selectedActorId)
    ? selectedActorId
    : (filteredActors[0]?.id ?? "");
  const selectedActor = actors.find((actor) => actor.id === effectiveSelectedActorId) ?? null;

  async function handleCompare() {
    if (!effectiveSelectedActorId) {
      return;
    }

    setCompareLoading(true);
    setError(null);
    setComparison(null);

    try {
      setComparison(await compareActor(effectiveSelectedActorId, metric, topN));
    } catch (apiError) {
      setError(apiError instanceof Error ? apiError.message : "Unable to compare actor");
    } finally {
      setCompareLoading(false);
    }
  }

  return (
    <section className="comparison-workspace" aria-labelledby="comparison-title">
      <div className="workspace-header">
        <div>
          <p className="eyebrow">Actor Comparison</p>
          <h1 id="comparison-title">Compare ATT&CK profiles</h1>
        </div>
        <div className="source-pill">
          <BarChart3 size={16} aria-hidden="true" />
          <span>MITRE dataset</span>
        </div>
      </div>

      <div className="comparison-layout">
        <form
          className="control-panel"
          onSubmit={(event) => {
            event.preventDefault();
            void handleCompare();
          }}
        >
          <label className="field-group" htmlFor="actor-search">
            <span>Search actors</span>
            <div className="search-field">
              <Search size={17} aria-hidden="true" />
              <input
                id="actor-search"
                type="search"
                value={actorQuery}
                onChange={(event) => {
                  setActorQuery(event.target.value);
                }}
                placeholder="APT, alias, group"
              />
            </div>
          </label>

          <label className="field-group" htmlFor="actor-select">
            <span>Actor</span>
            <select
              id="actor-select"
              value={effectiveSelectedActorId}
              disabled={actorsLoading || filteredActors.length === 0}
              onChange={(event) => {
                setSelectedActorId(event.target.value);
              }}
            >
              {filteredActors.map((actor) => (
                <option key={actor.id} value={actor.id}>
                  {actor.name} ({actor.technique_count})
                </option>
              ))}
            </select>
          </label>

          <div className="selected-actor">
            <p>{selectedActor?.name ?? "No actor selected"}</p>
            <span>{selectedActor ? `${selectedActor.technique_count} techniques` : "Load MITRE data first"}</span>
          </div>

          <label className="field-group" htmlFor="metric-select">
            <span>Metric</span>
            <select
              id="metric-select"
              value={metric}
              onChange={(event) => {
                setMetric(event.target.value as SimilarityMetric);
              }}
            >
              <option value="jaccard">Jaccard</option>
              <option value="jaccard_weighted">Weighted Jaccard</option>
            </select>
          </label>

          <label className="field-group" htmlFor="top-n-input">
            <span>Results</span>
            <input
              id="top-n-input"
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

          <button
            className="primary-action"
            type="submit"
            disabled={!effectiveSelectedActorId || actorsLoading || compareLoading}
          >
            {compareLoading ? (
              <Loader2 className="spin" size={18} aria-hidden="true" />
            ) : (
              <BarChart3 size={18} aria-hidden="true" />
            )}
            <span>{compareLoading ? "Comparing" : "Compare"}</span>
          </button>

          {actorsLoading ? <StatusMessage tone="neutral" message="Loading actors" /> : null}
          {error ? <StatusMessage tone="error" message={error} /> : null}
        </form>

        <ComparisonResults comparison={comparison} loading={compareLoading} />
      </div>
    </section>
  );
}

function ComparisonResults({ comparison, loading }: { comparison: ActorComparisonResponse | null; loading: boolean }) {
  if (loading) {
    return (
      <section className="results-panel" aria-live="polite">
        <div className="empty-state">
          <Loader2 className="spin" size={22} aria-hidden="true" />
          <p>Ranking actors</p>
        </div>
      </section>
    );
  }

  if (!comparison) {
    return (
      <section className="results-panel">
        <div className="empty-state">
          <BarChart3 size={24} aria-hidden="true" />
          <p>Select an actor and run a comparison.</p>
        </div>
      </section>
    );
  }

  return (
    <section className="results-panel" aria-live="polite">
      <div className="results-header">
        <div>
          <p className="panel-label">Input</p>
          <h2>{comparison.input_name}</h2>
        </div>
        <span className="metric-label">{comparison.metric === "jaccard" ? "Jaccard" : "Weighted"}</span>
      </div>

      <ol className="result-list">
        {comparison.results.map((result, index) => (
          <li className="result-row" key={result.matched_entity_id}>
            <div className="rank">{index + 1}</div>
            <div className="result-main">
              <div className="result-title-line">
                <h3>{result.matched_entity_name}</h3>
                <strong>{formatScore(result.score)}</strong>
              </div>
              <div className="result-meta">
                <span>{result.shared_techniques.length} shared techniques</span>
                <span>{result.unique_to_matched_entity.length} unique matched</span>
                <span>{result.unique_to_input.length} unique input</span>
              </div>
              <TechniquePreview techniques={result.shared_techniques} />
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

function TechniquePreview({ techniques }: { techniques: string[] }) {
  if (techniques.length === 0) {
    return <p className="technique-preview muted">No shared techniques</p>;
  }

  const visible = techniques.slice(0, 8);
  const hiddenCount = techniques.length - visible.length;

  return (
    <p className="technique-preview">
      {visible.join(", ")}
      {hiddenCount > 0 ? ` +${hiddenCount} more` : ""}
    </p>
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

function formatScore(score: number): string {
  return `${Math.round(score * 100)}%`;
}
