import { AlertCircle, BarChart3, Clock3, Loader2, Play, RefreshCw, Search, Trash2, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import {
  compareActor,
  compareTTPProfile,
  deleteAnalysis,
  getActorDetail,
  getActors,
  getAnalyses,
  getAnalysisDetail,
  getTechniques,
  getTTPProfiles
} from "../api/client";
import {
  buildComparableProfiles,
  filterComparableProfiles,
  groupComparableProfiles,
  profileDetail,
  profileTypeLabel,
  type ComparableProfile
} from "../api/profileLibraryUtils";
import {
  savedAnalysisDateLabel,
  savedAnalysisInputTypeLabel,
  savedAnalysisMetricLabel,
  savedAnalysisTacticScopeLabel,
  savedAnalysisTargetScopeLabel,
  savedAnalysisToViewModel
} from "../api/savedAnalysisUtils";
import { formatTactic, splitTactics, techniqueLookupFromList } from "../api/ttpProfileUtils";
import type {
  ActorComparisonResponse,
  ActorDetail,
  ActorListItem,
  AnalysisDetail,
  AnalysisResponse,
  PrimarySourceName,
  SimilarityMetric,
  TechniqueListItem,
  TTPProfile
} from "../api/types";
import { ComparisonResultTabs } from "./ComparisonResultTabs";

const DEFAULT_TOP_N = 10;
type ComparisonScope = "all" | "selected";

export function ActorComparisonPanel({
  activeSource = "mitre",
  onActorCountChange
}: {
  activeSource?: PrimarySourceName;
  onActorCountChange?: (count: number) => void;
}) {
  const [actors, setActors] = useState<ActorListItem[]>([]);
  const [customProfiles, setCustomProfiles] = useState<TTPProfile[]>([]);
  const [techniques, setTechniques] = useState<TechniqueListItem[]>([]);
  const [sourceQuery, setSourceQuery] = useState("");
  const [selectedSourceKey, setSelectedSourceKey] = useState("");
  const [selectedTactic, setSelectedTactic] = useState("all");
  const [scope, setScope] = useState<ComparisonScope>("all");
  const [targetQuery, setTargetQuery] = useState("");
  const [selectedTargetKeys, setSelectedTargetKeys] = useState<string[]>([]);
  const [metric, setMetric] = useState<SimilarityMetric>("jaccard");
  const [topN, setTopN] = useState(DEFAULT_TOP_N);
  const [loading, setLoading] = useState(true);
  const [compareLoading, setCompareLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [comparison, setComparison] = useState<ActorComparisonResponse | null>(null);
  const [savedAnalysesRefreshKey, setSavedAnalysesRefreshKey] = useState(0);
  const [selectedSourceDetail, setSelectedSourceDetail] = useState<ActorDetail | null>(null);

  useEffect(() => {
    Promise.all([getActors(), getTTPProfiles(), getTechniques()])
      .then(([actorItems, customProfileItems, techniqueItems]) => {
        setActors(actorItems);
        setCustomProfiles(customProfileItems);
        setTechniques(techniqueItems);
        const firstProfile = buildComparableProfiles(actorItems, customProfileItems)[0];
        setSelectedSourceKey(firstProfile?.key ?? "");
        onActorCountChange?.(actorItems.length);
      })
      .catch((apiError: unknown) => {
        setError(apiError instanceof Error ? apiError.message : "Unable to load comparable profiles");
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  const comparableProfiles = useMemo(() => buildComparableProfiles(actors, customProfiles), [actors, customProfiles]);
  const sourceProfiles = useMemo(
    () => filterComparableProfiles(comparableProfiles, sourceQuery),
    [comparableProfiles, sourceQuery]
  );
  const selectedSource =
    comparableProfiles.find((profile) => profile.key === selectedSourceKey) ?? comparableProfiles[0] ?? null;
  const visibleSourceProfiles = useMemo(() => {
    if (!selectedSource || sourceProfiles.some((profile) => profile.key === selectedSource.key)) {
      return sourceProfiles;
    }
    return [selectedSource, ...sourceProfiles];
  }, [selectedSource, sourceProfiles]);
  const targetProfiles = useMemo(
    () => comparableProfiles.filter((profile) => profile.key !== selectedSource?.key),
    [comparableProfiles, selectedSource?.key]
  );
  const filteredTargetProfiles = useMemo(
    () => filterComparableProfiles(targetProfiles, targetQuery),
    [targetProfiles, targetQuery]
  );
  const selectedTargets = selectedTargetKeys
    .map((key) => targetProfiles.find((profile) => profile.key === key))
    .filter((profile): profile is ComparableProfile => Boolean(profile));
  const selectedActorTargetIds = selectedTargets.filter((target) => target.type === "actor").map((target) => target.id);
  const selectedCustomTargetCount = selectedTargets.filter((target) => target.type === "custom").length;
  const techniqueLookup = useMemo(() => techniqueLookupFromList(techniques), [techniques]);
  const availableTactics = useMemo(
    () =>
      Array.from(
        new Set(techniques.flatMap((technique) => splitTactics(technique.tactic)).filter(Boolean))
      ).sort((left, right) => formatTactic(left).localeCompare(formatTactic(right))),
    [techniques]
  );
  const selectedTactics = selectedTactic === "all" ? undefined : [selectedTactic];
  const tacticScopeLabel = selectedTactic === "all" ? "All tactics" : formatTactic(selectedTactic);
  const comparisonScopeLabel =
    scope === "all" ? "All actor profiles" : selectedTargets.map((target) => target.name).join(", ") || "No target profiles selected";
  const selectedCustomTargetNotice =
    selectedCustomTargetCount > 0
      ? "Custom profile targets are visible for future support; current comparison runs against actor profiles only."
      : null;
  const compareDisabled =
    !selectedSource || loading || compareLoading || (scope === "selected" && selectedActorTargetIds.length === 0);

  async function handleCompare() {
    if (!selectedSource) {
      setError("Select a source profile before comparing.");
      return;
    }
    if (scope === "selected" && selectedTargets.length === 0) {
      setError("Select at least one target profile before comparing.");
      return;
    }
    if (scope === "selected" && selectedActorTargetIds.length === 0) {
      setError("Select at least one actor profile target. Custom TTP profile targets are visible for future support.");
      return;
    }
    if (selectedTactic !== "all" && !availableTactics.includes(selectedTactic.toLowerCase())) {
      setError("Select a valid tactic scope before comparing.");
      return;
    }

    setCompareLoading(true);
    setError(null);
    setComparison(null);

    try {
      if (selectedSource.type === "actor") {
        setComparison(
          await compareActor(
            selectedSource.id,
            metric,
            topN,
            scope === "selected" ? selectedActorTargetIds : undefined,
            selectedTactics
          )
        );
      } else {
        setComparison(
          await compareTTPProfile({
            profileId: selectedSource.id,
            metric,
            topN,
            targetIds: scope === "selected" ? selectedActorTargetIds : undefined,
            tactics: selectedTactics
          })
        );
      }
    } catch (apiError) {
      setError(apiError instanceof Error ? apiError.message : "Unable to compare profiles");
    } finally {
      setCompareLoading(false);
    }
  }

  // Fetch actor detail whenever an actor source profile is selected
  useEffect(() => {
    if (selectedSource?.type === "actor") {
      setSelectedSourceDetail(null);
      getActorDetail(selectedSource.id).then(setSelectedSourceDetail).catch(() => {});
    } else {
      setSelectedSourceDetail(null);
    }
  }, [selectedSource?.id, selectedSource?.type]);

  function handleSourceChange(nextSourceKey: string) {
    setSelectedSourceKey(nextSourceKey);
    setSelectedTargetKeys((currentKeys) => currentKeys.filter((key) => key !== nextSourceKey));
    setComparison(null);
    setError(null);
  }

  const dynamicTitle = selectedSource
    ? `Who looks like ${selectedSource.name}?`
    : "Compare TTP profiles";

  const metricHint: Record<SimilarityMetric, string> = {
    jaccard: "Counts how many TTPs both actors share relative to their combined set.",
    jaccard_weighted: "Rare techniques contribute more — penalizes common, well-known TTPs.",
    tactic_weighted_jaccard: "Favours coverage breadth across kill-chain phases — useful for strategic comparisons.",
    software_weighted_jaccard: "Incorporates shared malware and tools alongside technique overlap.",
    holistic: "Multi-dimensional: techniques (60%) + target sectors (15%) + countries (10%) + CVEs (10%) + motivation (5%). Dimensions with no data on either side are excluded and weights renormalized."
  };

  return (
    <section className="comparison-workspace" aria-labelledby="comparison-title">
      <div className="workspace-header">
        <div>
          <p className="eyebrow">Compare · Workspace</p>
          <h1 id="comparison-title">{dynamicTitle}</h1>
          {selectedSource ? (
            <p className="scope-summary" style={{ marginTop: 4 }}>
              Rank actors by TTP overlap against this profile. Filter by tactic or weight by coverage.
            </p>
          ) : null}
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <div className="source-pill">
            <span className="source-pill-dot" aria-hidden="true" />
            <span>{activeSource === "mitre" ? "MITRE ATT&CK" : "OpenCTI"}</span>
          </div>
          <div className="source-pill">
            <BarChart3 size={13} aria-hidden="true" />
            <span>{actors.length} actors</span>
            {techniques.length > 0 ? (
              <>
                <span style={{ color: "var(--text-4)" }}>·</span>
                <span>{techniques.length} techniques</span>
              </>
            ) : null}
          </div>
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
          {/* Search */}
          <div className="field-group">
            <span>Find source profile</span>
            <div className="search-field">
              <Search size={15} aria-hidden="true" />
              <input
                type="search"
                value={sourceQuery}
                onChange={(event) => setSourceQuery(event.target.value)}
                placeholder="Actor name, alias, code…"
              />
            </div>
          </div>

          {/* Source dropdown */}
          <div className="field-group">
            <span>Source profile</span>
            <select
              value={selectedSource?.key ?? ""}
              disabled={loading || comparableProfiles.length === 0}
              onChange={(event) => handleSourceChange(event.target.value)}
            >
              <ProfileOptionGroups profiles={visibleSourceProfiles} />
            </select>
          </div>

          {/* Rich profile card */}
          {selectedSource ? (
            <SourceProfileCard profile={selectedSource} detail={selectedSourceDetail} />
          ) : null}

          {/* Metric */}
          <div className="field-group">
            <span>Similarity metric</span>
            <select
              value={metric}
              onChange={(event) => setMetric(event.target.value as SimilarityMetric)}
            >
              <option value="jaccard">Jaccard</option>
              <option value="jaccard_weighted">Weighted Jaccard</option>
              <option value="tactic_weighted_jaccard">Tactic-weighted Jaccard</option>
              <option value="software_weighted_jaccard">Software-weighted Jaccard</option>
              <option value="holistic">Holistic (TTPs + sectors + countries + CVEs + motivation)</option>
            </select>
          </div>

          {/* Top N stepper */}
          <div className="field-group">
            <span>Top results</span>
            <div className="topn-stepper">
              <button
                type="button"
                className="topn-btn"
                onClick={() => setTopN((n) => Math.max(1, n - 1))}
                aria-label="Decrease"
              >−</button>
              <span className="topn-value">{topN}</span>
              <button
                type="button"
                className="topn-btn"
                onClick={() => setTopN((n) => Math.min(100, n + 1))}
                aria-label="Increase"
              >+</button>
            </div>
          </div>

          {/* Tactic scope */}
          <div className="field-group">
            <span>Tactic scope</span>
            <select
              value={selectedTactic}
              disabled={loading || availableTactics.length === 0}
              onChange={(event) => setSelectedTactic(event.target.value)}
            >
              <option value="all">All tactics</option>
              {availableTactics.map((tactic) => (
                <option key={tactic} value={tactic}>{formatTactic(tactic)}</option>
              ))}
            </select>
          </div>

          {/* Target scope — segmented buttons */}
          <div className="field-group">
            <span>Target scope</span>
            <div className="segmented-control">
              <button
                type="button"
                className={scope === "all" ? "active" : ""}
                onClick={() => setScope("all")}
              >
                All actors
              </button>
              <button
                type="button"
                className={scope === "selected" ? "active" : ""}
                onClick={() => setScope("selected")}
              >
                Selected
              </button>
            </div>
          </div>

          {/* Target picker (when selected mode) */}
          {scope === "selected" ? (
            <div className="target-selector">
              <div className="field-group">
                <span>Target profiles</span>
                <div className="search-field">
                  <Search size={15} aria-hidden="true" />
                  <input
                    type="search"
                    value={targetQuery}
                    onChange={(event) => setTargetQuery(event.target.value)}
                    placeholder="Search profiles"
                  />
                </div>
              </div>
              <ProfilePickerGroups
                profiles={filteredTargetProfiles}
                selectedKeys={selectedTargetKeys}
                onSelect={(profile) => {
                  setSelectedTargetKeys((currentKeys) => [...currentKeys, profile.key]);
                }}
              />
              <div className="chip-list" style={{ marginTop: 4 }}>
                {selectedTargets.map((target) => (
                  <button
                    className="technique-chip"
                    key={target.key}
                    type="button"
                    onClick={() => {
                      setSelectedTargetKeys((currentKeys) => currentKeys.filter((key) => key !== target.key));
                    }}
                  >
                    <span>{target.name}</span>
                    <X size={12} aria-hidden="true" />
                  </button>
                ))}
                {selectedTargets.length === 0 ? <span className="muted" style={{ fontSize: "0.8rem" }}>No profiles selected</span> : null}
              </div>
            </div>
          ) : null}

          {/* Compare button */}
          <button
            className="primary-action compare-run-btn"
            type="submit"
            disabled={compareDisabled}
          >
            {compareLoading ? (
              <Loader2 className="spin" size={16} aria-hidden="true" />
            ) : (
              <Play size={14} aria-hidden="true" />
            )}
            <span>{compareLoading ? "Running comparison…" : "Run comparison"}</span>
          </button>

          {/* Metric hint */}
          {metric !== "jaccard" ? (
            <p className="metric-hint">{metricHint[metric]}</p>
          ) : null}

          {loading ? <StatusMessage tone="neutral" message="Loading profiles…" /> : null}
          {selectedCustomTargetNotice ? <StatusMessage tone="neutral" message={selectedCustomTargetNotice} /> : null}
          {error ? <StatusMessage tone="error" message={error} /> : null}
        </form>

        <ComparisonResults
          comparison={comparison}
          loading={compareLoading}
          topN={topN}
          comparisonScopeLabel={comparisonScopeLabel}
          tacticScopeLabel={tacticScopeLabel}
          tactics={selectedTactics}
          targetIds={scope === "selected" ? selectedActorTargetIds : undefined}
          actorAliases={Object.fromEntries(
            actors
              .filter((a) => a.aliases.length > 0)
              .map((a) => [a.id, a.aliases.find((al) => al !== a.name) ?? a.aliases[0]])
              .filter((entry): entry is [string, string] => !!entry[1])
          )}
          onAnalysisSaved={() => {
            setSavedAnalysesRefreshKey((currentKey) => currentKey + 1);
          }}
          onRerun={() => setComparison(null)}
          techniqueLookup={techniqueLookup}
        />
      </div>

      <SavedAnalysesPanel
        refreshKey={savedAnalysesRefreshKey}
        techniqueLookup={techniqueLookup}
      />
    </section>
  );
}

function SourceProfileCard({
  profile,
  detail
}: {
  profile: ComparableProfile;
  detail: ActorDetail | null;
}) {
  const aliases = (detail?.aliases ?? profile.aliases ?? []).filter((a) => a !== profile.name);
  const firstAlias = aliases[0];

  return (
    <div className="source-card">
      <div className="source-card-header">
        <div className="source-card-name">
          <span>{profile.name}</span>
          {firstAlias ? <span className="source-card-alias">{firstAlias}</span> : null}
        </div>
        <span className="source-card-type-badge">
          {profile.type === "actor" ? "ACTOR" : "CUSTOM"}
        </span>
      </div>

      <div className="source-card-meta">
        <span className="source-card-stat">
          ⟨{profile.technique_count}⟩ techniques
        </span>
        {detail?.motivation ? (
          <span className="source-card-tag">{detail.motivation}</span>
        ) : null}
      </div>

      {detail?.target_sectors && detail.target_sectors.length > 0 ? (
        <div className="source-card-chips">
          {detail.target_sectors.slice(0, 4).map((s) => (
            <span className="source-card-chip" key={s}>{s}</span>
          ))}
          {detail.target_sectors.length > 4 ? (
            <span className="source-card-chip source-card-chip--more">+{detail.target_sectors.length - 4}</span>
          ) : null}
        </div>
      ) : null}

    </div>
  );
}

function ProfileOptionGroups({ profiles }: { profiles: ComparableProfile[] }) {
  return (
    <>
      {groupComparableProfiles(profiles).map((group) => (
        <optgroup key={group.label} label={group.label}>
          {group.options.map((profile) => (
            <option key={profile.key} value={profile.key}>
              {profile.name} ({profile.technique_count})
            </option>
          ))}
        </optgroup>
      ))}
    </>
  );
}

function ProfilePickerGroups({
  profiles,
  selectedKeys,
  onSelect
}: {
  profiles: ComparableProfile[];
  selectedKeys: string[];
  onSelect: (profile: ComparableProfile) => void;
}) {
  const selectedKeySet = new Set(selectedKeys);
  const groups = groupComparableProfiles(profiles.filter((profile) => !selectedKeySet.has(profile.key)));

  return (
    <div className="profile-picker-list">
      {groups.map((group) => (
        <div className="target-picker-group" key={group.label}>
          <div className="mini-header">
            <strong>{group.label}</strong>
            <span>{group.options.length}</span>
          </div>
          <div className="target-picker-list">
            {group.options.length === 0 ? <p className="muted">No matching profiles found</p> : null}
            {group.options.map((profile) => (
              <button
                className="technique-option target-option"
                key={profile.key}
                type="button"
                onClick={() => onSelect(profile)}
              >
                <span>{profile.name}</span>
                <small>{profileTypeLabel(profile.type)} - {profile.technique_count} techniques</small>
              </button>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function ComparisonResults({
  comparison,
  loading,
  topN,
  comparisonScopeLabel,
  tacticScopeLabel,
  tactics,
  targetIds,
  actorAliases,
  onAnalysisSaved,
  onRerun,
  techniqueLookup
}: {
  comparison: ActorComparisonResponse | null;
  loading: boolean;
  topN: number;
  comparisonScopeLabel: string;
  tacticScopeLabel: string;
  tactics?: string[];
  targetIds?: string[];
  actorAliases?: Record<string, string>;
  onAnalysisSaved: () => void;
  onRerun?: () => void;
  techniqueLookup: ReturnType<typeof techniqueLookupFromList>;
}) {
  if (loading) {
    return (
      <section className="results-panel" aria-live="polite">
        <div className="empty-state">
          <Loader2 className="spin" size={22} aria-hidden="true" />
          <p>Ranking comparable profiles</p>
        </div>
      </section>
    );
  }

  if (!comparison) {
    return (
      <section className="results-panel">
        <div className="empty-state">
          <BarChart3 size={24} aria-hidden="true" />
          <p>Select a source profile to start comparison.</p>
        </div>
      </section>
    );
  }

  const canExport = comparison.results.length > 0;

  if (!canExport) {
    return (
      <section className="results-panel" aria-live="polite">
        <div className="results-header">
          <div>
            <p className="panel-label">Source profile</p>
            <h2>{comparison.input_name}</h2>
            <p className="scope-summary">Comparing against: {comparisonScopeLabel}</p>
            <p className="scope-summary">Similarity scope: {tacticScopeLabel}</p>
          </div>
          <span className="metric-label">{metricLabel(comparison.metric)}</span>
        </div>
        <div className="empty-state">
          <BarChart3 size={24} aria-hidden="true" />
          <p>No matching actor profiles found. Load MITRE data or choose another source profile.</p>
        </div>
      </section>
    );
  }

  return (
    <ComparisonResultTabs
      comparison={comparison}
      topN={topN}
      comparisonScopeLabel={comparisonScopeLabel}
      tacticScopeLabel={tacticScopeLabel}
      tactics={tactics}
      targetIds={targetIds}
      actorAliases={actorAliases}
      onAnalysisSaved={onAnalysisSaved}
      onRerun={onRerun}
      techniqueLookup={techniqueLookup}
    />
  );
}

function SavedAnalysesPanel({
  refreshKey,
  techniqueLookup
}: {
  refreshKey: number;
  techniqueLookup: ReturnType<typeof techniqueLookupFromList>;
}) {
  const [analyses, setAnalyses] = useState<AnalysisResponse[]>([]);
  const [selectedAnalysisId, setSelectedAnalysisId] = useState<string | null>(null);
  const [selectedAnalysis, setSelectedAnalysis] = useState<AnalysisDetail | null>(null);
  const [loadingList, setLoadingList] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deleteMessage, setDeleteMessage] = useState<string | null>(null);
  const hasSelectedAnalysisDetail = Boolean(selectedAnalysis);

  useEffect(() => {
    let ignore = false;

    getAnalyses()
      .then((items) => {
        if (ignore) {
          return;
        }
        setAnalyses(items);
        setSelectedAnalysisId((currentId) => {
          const nextId = currentId && items.some((item) => item.id === currentId) ? currentId : items[0]?.id ?? null;
          if (nextId && (nextId !== currentId || !hasSelectedAnalysisDetail)) {
            setLoadingDetail(true);
          }
          return nextId;
        });
        if (items.length === 0) {
          setSelectedAnalysis(null);
          setLoadingDetail(false);
        }
      })
      .catch((apiError: unknown) => {
        if (!ignore) {
          setError(apiError instanceof Error ? apiError.message : "Unable to load saved analyses");
        }
      })
      .finally(() => {
        if (!ignore) {
          setLoadingList(false);
        }
      });

    return () => {
      ignore = true;
    };
  }, [hasSelectedAnalysisDetail, refreshKey]);

  useEffect(() => {
    if (!selectedAnalysisId) {
      return;
    }

    let ignore = false;
    getAnalysisDetail(selectedAnalysisId)
      .then((detail) => {
        if (!ignore) {
          setSelectedAnalysis(detail);
        }
      })
      .catch((apiError: unknown) => {
        if (!ignore) {
          setSelectedAnalysis(null);
          setError(apiError instanceof Error ? apiError.message : "Unable to load saved analysis detail");
        }
      })
      .finally(() => {
        if (!ignore) {
          setLoadingDetail(false);
        }
      });

    return () => {
      ignore = true;
    };
  }, [selectedAnalysisId]);

  async function handleDeleteSelected() {
    if (!selectedAnalysis) {
      return;
    }

    if (!window.confirm(`Delete saved analysis "${selectedAnalysis.input_name}"? This cannot be undone.`)) {
      return;
    }

    setDeleting(true);
    setError(null);
    setDeleteMessage(null);

    try {
      await deleteAnalysis(selectedAnalysis.id);
      const nextAnalyses = analyses.filter((item) => item.id !== selectedAnalysis.id);
      setAnalyses(nextAnalyses);
      setSelectedAnalysisId(nextAnalyses[0]?.id ?? null);
      setSelectedAnalysis(null);
      setDeleteMessage("Saved analysis deleted.");
    } catch (apiError) {
      setError(apiError instanceof Error ? apiError.message : "Unable to delete saved analysis");
    } finally {
      setDeleting(false);
    }
  }

  const selectedViewModel = selectedAnalysis ? savedAnalysisToViewModel(selectedAnalysis) : null;

  return (
    <section className="saved-analyses-section" aria-labelledby="saved-analyses-title">
      <div className="workspace-header saved-analyses-heading">
        <div>
          <p className="eyebrow">Saved Analyses</p>
          <h2 id="saved-analyses-title">Saved Analyses</h2>
        </div>
        <button
          className="secondary-action refresh-action"
          type="button"
          disabled={loadingList}
          onClick={() => {
            setDeleteMessage(null);
            setLoadingList(true);
            setError(null);
            getAnalyses()
              .then((items) => {
                setAnalyses(items);
                if (items.length === 0) {
                  setSelectedAnalysis(null);
                  setLoadingDetail(false);
                }
                setSelectedAnalysisId((currentId) => {
                  const nextId = currentId && items.some((item) => item.id === currentId) ? currentId : items[0]?.id ?? null;
                  if (nextId && (nextId !== currentId || !hasSelectedAnalysisDetail)) {
                    setLoadingDetail(true);
                  }
                  return nextId;
                });
              })
              .catch((apiError: unknown) => {
                setError(apiError instanceof Error ? apiError.message : "Unable to refresh saved analyses");
              })
              .finally(() => {
                setLoadingList(false);
              });
          }}
        >
          <RefreshCw size={16} aria-hidden="true" />
          <span>Refresh</span>
        </button>
      </div>

      <div className="saved-analyses-layout">
        <section className="control-panel saved-analysis-list-panel" aria-label="Saved analysis list">
          {loadingList ? (
            <div className="empty-state compact-empty-state">
              <Loader2 className="spin" size={22} aria-hidden="true" />
              <p>Loading saved analyses</p>
            </div>
          ) : null}

          {!loadingList && analyses.length === 0 ? (
            <div className="empty-state compact-empty-state">
              <Clock3 size={24} aria-hidden="true" />
              <p>No saved analyses yet. Run a comparison and click Save analysis.</p>
            </div>
          ) : null}

          {!loadingList && analyses.length > 0 ? (
            <div className="saved-analysis-list">
              {analyses.map((analysis) => (
                <button
                  className={`saved-analysis-item ${analysis.id === selectedAnalysisId ? "active" : ""}`}
                  key={analysis.id}
                  type="button"
                  onClick={() => {
                    setDeleteMessage(null);
                    setError(null);
                    if (analysis.id !== selectedAnalysisId) {
                      setLoadingDetail(true);
                    }
                    setSelectedAnalysisId(analysis.id);
                  }}
                >
                  <span className="saved-analysis-name">{analysis.input_name}</span>
                  <span>{savedAnalysisInputTypeLabel(analysis.input_type)}</span>
                  <span>{savedAnalysisMetricLabel(analysis.metric)} - {savedAnalysisTacticScopeLabel(analysis.tactics)}</span>
                  <span>Top {analysis.top_n} - {savedAnalysisDateLabel(analysis.created_at)}</span>
                </button>
              ))}
            </div>
          ) : null}

          {deleteMessage ? <StatusMessage tone="neutral" message={deleteMessage} /> : null}
          {error ? <StatusMessage tone="error" message={error} /> : null}
        </section>

        <section className="saved-analysis-detail-panel">
          {loadingDetail ? (
            <section className="results-panel" aria-live="polite">
              <div className="empty-state">
                <Loader2 className="spin" size={22} aria-hidden="true" />
                <p>Loading saved analysis detail</p>
              </div>
            </section>
          ) : null}

          {!loadingDetail && !selectedAnalysis ? (
            <section className="results-panel">
              <div className="empty-state">
                <Clock3 size={24} aria-hidden="true" />
                <p>Select a saved analysis to inspect its results.</p>
              </div>
            </section>
          ) : null}

          {!loadingDetail && selectedAnalysis && selectedViewModel ? (
            <div className="saved-analysis-detail-stack">
              <div className="saved-analysis-summary-bar">
                <div>
                  <p className="panel-label">Saved analysis</p>
                  <h3>{selectedAnalysis.input_name}</h3>
                  <p>
                    {savedAnalysisInputTypeLabel(selectedAnalysis.input_type)} - {savedAnalysisMetricLabel(selectedAnalysis.metric)}
                  </p>
                  <p>
                    {selectedViewModel.tacticScopeLabel} - {savedAnalysisTargetScopeLabel(selectedAnalysis.target_ids)} - Top{" "}
                    {selectedAnalysis.top_n}
                  </p>
                  <p>{savedAnalysisDateLabel(selectedAnalysis.created_at)}</p>
                </div>
                <button
                  className="danger-action"
                  type="button"
                  disabled={deleting}
                  onClick={() => void handleDeleteSelected()}
                >
                  <Trash2 size={16} aria-hidden="true" />
                  <span>{deleting ? "Deleting" : "Delete"}</span>
                </button>
              </div>

              <ComparisonResultTabs
                comparison={selectedViewModel.comparison}
                topN={selectedViewModel.topN}
                comparisonScopeLabel={selectedViewModel.comparisonScopeLabel}
                tacticScopeLabel={selectedViewModel.tacticScopeLabel}
                tactics={selectedViewModel.tactics}
                targetIds={selectedViewModel.targetIds}
                canSave={false}
                techniqueLookup={techniqueLookup}
              />
            </div>
          ) : null}
        </section>
      </div>
    </section>
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

