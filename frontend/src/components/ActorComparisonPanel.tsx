import { AlertCircle, BarChart3, Clock3, Loader2, RefreshCw, Search, Trash2, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import {
  compareActor,
  compareTTPProfile,
  deleteAnalysis,
  getActors,
  getAnalyses,
  getAnalysisDetail,
  getEnrichmentOptions,
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
import { formatTactic, techniqueLookupFromList } from "../api/ttpProfileUtils";
import type {
  ActorComparisonResponse,
  ActorListItem,
  AnalysisDetail,
  AnalysisResponse,
  EnrichmentOptions,
  PrimarySourceName,
  SimilarityMetric,
  TechniqueListItem,
  TTPProfile
} from "../api/types";
import { ComparisonResultTabs } from "./ComparisonResultTabs";
import { EnrichmentFilterPanel } from "./EnrichmentFilterPanel";

const DEFAULT_TOP_N = 10;
type ComparisonScope = "all" | "selected";

export function ActorComparisonPanel({ activeSource = "mitre" }: { activeSource?: PrimarySourceName }) {
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
  const [enrichmentOptions, setEnrichmentOptions] = useState<EnrichmentOptions>({ sectors: [], countries: [] });
  const [selectedSectors, setSelectedSectors] = useState<string[]>([]);
  const [selectedCountries, setSelectedCountries] = useState<string[]>([]);

  useEffect(() => {
    Promise.all([getActors(), getTTPProfiles(), getTechniques()])
      .then(([actorItems, customProfileItems, techniqueItems]) => {
        setActors(actorItems);
        setCustomProfiles(customProfileItems);
        setTechniques(techniqueItems);
        const firstProfile = buildComparableProfiles(actorItems, customProfileItems)[0];
        setSelectedSourceKey(firstProfile?.key ?? "");
      })
      .catch((apiError: unknown) => {
        setError(apiError instanceof Error ? apiError.message : "Unable to load comparable profiles");
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    if (activeSource === "opencti") {
      getEnrichmentOptions()
        .then(setEnrichmentOptions)
        .catch(() => {});
    } else {
      setEnrichmentOptions({ sectors: [], countries: [] });
      setSelectedSectors([]);
      setSelectedCountries([]);
    }
  }, [activeSource]);

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
      Array.from(new Set(techniques.map((technique) => technique.tactic).filter(Boolean))).sort((left, right) =>
        formatTactic(left).localeCompare(formatTactic(right))
      ),
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
    if (selectedTactic !== "all" && !availableTactics.includes(selectedTactic)) {
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
            selectedTactics,
            selectedSectors.length > 0 ? selectedSectors : undefined,
            selectedCountries.length > 0 ? selectedCountries : undefined
          )
        );
      } else {
        setComparison(
          await compareTTPProfile({
            profileId: selectedSource.id,
            metric,
            topN,
            targetIds: scope === "selected" ? selectedActorTargetIds : undefined,
            tactics: selectedTactics,
            filterSectors: selectedSectors.length > 0 ? selectedSectors : undefined,
            filterCountries: selectedCountries.length > 0 ? selectedCountries : undefined
          })
        );
      }
    } catch (apiError) {
      setError(apiError instanceof Error ? apiError.message : "Unable to compare profiles");
    } finally {
      setCompareLoading(false);
    }
  }

  function handleSourceChange(nextSourceKey: string) {
    setSelectedSourceKey(nextSourceKey);
    setSelectedTargetKeys((currentKeys) => currentKeys.filter((key) => key !== nextSourceKey));
    setComparison(null);
    setError(null);
  }

  return (
    <section className="comparison-workspace" aria-labelledby="comparison-title">
      <div className="workspace-header">
        <div>
          <p className="eyebrow">Compare</p>
          <h1 id="comparison-title">Compare TTP profiles</h1>
        </div>
        <div className="source-pill">
          <BarChart3 size={16} aria-hidden="true" />
          <span>
            {activeSource === "mitre" ? "MITRE ATT&CK" : "OpenCTI"} · {comparableProfiles.length} profiles
          </span>
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
          <label className="field-group" htmlFor="source-profile-search">
            <span>Find source profile</span>
            <div className="search-field">
              <Search size={17} aria-hidden="true" />
              <input
                id="source-profile-search"
                type="search"
                value={sourceQuery}
                onChange={(event) => {
                  setSourceQuery(event.target.value);
                }}
                placeholder="Profile name, actor alias"
              />
            </div>
          </label>

          <label className="field-group" htmlFor="source-profile-select">
            <span>Source profile</span>
            <select
              id="source-profile-select"
              value={selectedSource?.key ?? ""}
              disabled={loading || comparableProfiles.length === 0}
              onChange={(event) => {
                handleSourceChange(event.target.value);
              }}
            >
              <ProfileOptionGroups profiles={visibleSourceProfiles} />
            </select>
          </label>

          <div className="selected-actor">
            <p>{selectedSource?.name ?? "No source profile selected"}</p>
            <span>{selectedSource ? profileDetail(selectedSource) : "Load profiles first"}</span>
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
              <option value="tactic_weighted_jaccard">Tactic weighted</option>
              <option value="software_weighted_jaccard">Software weighted</option>
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

          <label className="field-group" htmlFor="tactic-scope-select">
            <span>Similarity scope</span>
            <select
              id="tactic-scope-select"
              value={selectedTactic}
              disabled={loading || availableTactics.length === 0}
              onChange={(event) => {
                setSelectedTactic(event.target.value);
              }}
            >
              <option value="all">All tactics</option>
              {availableTactics.map((tactic) => (
                <option key={tactic} value={tactic}>
                  {formatTactic(tactic)}
                </option>
              ))}
            </select>
          </label>

          {(enrichmentOptions.sectors.length > 0 || enrichmentOptions.countries.length > 0) ? (
            <EnrichmentFilterPanel
              options={enrichmentOptions}
              selectedSectors={selectedSectors}
              selectedCountries={selectedCountries}
              onSectorsChange={setSelectedSectors}
              onCountriesChange={setSelectedCountries}
            />
          ) : null}

          <fieldset className="scope-selector">
            <legend>Target scope</legend>
            <label>
              <input
                type="radio"
                name="comparison-scope"
                value="all"
                checked={scope === "all"}
                onChange={() => {
                  setScope("all");
                }}
              />
              <span>Compare against all actor profiles</span>
            </label>
            <label>
              <input
                type="radio"
                name="comparison-scope"
                value="selected"
                checked={scope === "selected"}
                onChange={() => {
                  setScope("selected");
                }}
              />
              <span>Compare against selected profiles</span>
            </label>
          </fieldset>

          {scope === "selected" ? (
            <div className="target-selector">
              <label className="field-group" htmlFor="target-profile-search">
                <span>Target profiles</span>
                <div className="search-field">
                  <Search size={17} aria-hidden="true" />
                  <input
                    id="target-profile-search"
                    type="search"
                    value={targetQuery}
                    onChange={(event) => {
                      setTargetQuery(event.target.value);
                    }}
                    placeholder="Search comparable profiles"
                  />
                </div>
              </label>

              <ProfilePickerGroups
                profiles={filteredTargetProfiles}
                selectedKeys={selectedTargetKeys}
                onSelect={(profile) => {
                  setSelectedTargetKeys((currentKeys) => [...currentKeys, profile.key]);
                }}
              />

              <div className="selected-techniques">
                <div className="mini-header">
                  <strong>{selectedTargets.length} target profiles</strong>
                  {selectedCustomTargetCount > 0 ? <span className="field-hint">Custom targets pending</span> : null}
                </div>
                <div className="chip-list">
                  {selectedTargets.map((target) => (
                    <button
                      className={`technique-chip target-chip ${target.type === "custom" ? "profile-chip" : ""}`}
                      key={target.key}
                      type="button"
                      title={profileDetail(target)}
                      onClick={() => {
                        setSelectedTargetKeys((currentKeys) => currentKeys.filter((key) => key !== target.key));
                      }}
                    >
                      <span>{target.name}</span>
                      <X size={14} aria-hidden="true" />
                    </button>
                  ))}
                  {selectedTargets.length === 0 ? <span className="muted">No target profiles selected</span> : null}
                </div>
              </div>
            </div>
          ) : null}

          <button className="primary-action" type="submit" disabled={compareDisabled}>
            {compareLoading ? (
              <Loader2 className="spin" size={18} aria-hidden="true" />
            ) : (
              <BarChart3 size={18} aria-hidden="true" />
            )}
            <span>{compareLoading ? "Comparing" : "Compare"}</span>
          </button>

          {loading ? <StatusMessage tone="neutral" message="Loading comparable profiles" /> : null}
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
          filterSectors={selectedSectors.length > 0 ? selectedSectors : undefined}
          filterCountries={selectedCountries.length > 0 ? selectedCountries : undefined}
          onAnalysisSaved={() => {
            setSavedAnalysesRefreshKey((currentKey) => currentKey + 1);
          }}
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
  filterSectors,
  filterCountries,
  onAnalysisSaved,
  techniqueLookup
}: {
  comparison: ActorComparisonResponse | null;
  loading: boolean;
  topN: number;
  comparisonScopeLabel: string;
  tacticScopeLabel: string;
  tactics?: string[];
  targetIds?: string[];
  filterSectors?: string[];
  filterCountries?: string[];
  onAnalysisSaved: () => void;
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
      filterSectors={filterSectors}
      filterCountries={filterCountries}
      onAnalysisSaved={onAnalysisSaved}
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
                  {selectedViewModel.enrichmentFilterLabel ? (
                    <p style={{ fontSize: "0.82rem", color: "#2d6a4f" }}>
                      Filter: {selectedViewModel.enrichmentFilterLabel}
                    </p>
                  ) : null}
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

