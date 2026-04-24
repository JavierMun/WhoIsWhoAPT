import { AlertCircle, Download, FileJson, Loader2, Plus, Radar, Save, Search, Table, Upload, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { compareCustomSet, createCustomSet, getCustomSets, getTechniques } from "../api/client";
import { downloadComparisonExport } from "../api/exportUtils";
import {
  extractNavigatorTechniqueIds,
  formatTactic,
  groupTechniquesByTactic,
  parseTechniqueIds,
  unknownTechniqueIds,
  type NavigatorLayer
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

export function TTPProfilesPanel() {
  const [techniques, setTechniques] = useState<TechniqueListItem[]>([]);
  const [profiles, setProfiles] = useState<CustomTTPSet[]>([]);
  const [profileName, setProfileName] = useState("Observed TTP Profile");
  const [description, setDescription] = useState("");
  const [techniqueInput, setTechniqueInput] = useState("");
  const [selectedTechniqueIds, setSelectedTechniqueIds] = useState<string[]>([]);
  const [techniqueQuery, setTechniqueQuery] = useState("");
  const [tacticFilter, setTacticFilter] = useState("all");
  const [selectedProfileId, setSelectedProfileId] = useState("");
  const [metric, setMetric] = useState<SimilarityMetric>("jaccard_weighted");
  const [topN, setTopN] = useState(DEFAULT_TOP_N);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [comparing, setComparing] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [comparison, setComparison] = useState<ActorComparisonResponse | null>(null);

  useEffect(() => {
    Promise.all([getTechniques(), getCustomSets()])
      .then(([techniqueItems, profileItems]) => {
        setTechniques(techniqueItems);
        setProfiles(profileItems);
        setSelectedProfileId(profileItems[0]?.id ?? "");
      })
      .catch((apiError: unknown) => {
        setError(apiError instanceof Error ? apiError.message : "Unable to load TTP profile data");
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  const techniqueLookup = useMemo(
    () => new Map(techniques.map((technique) => [technique.technique_id, technique])),
    [techniques]
  );
  const validTechniqueIds = useMemo(() => new Set(techniques.map((technique) => technique.technique_id)), [techniques]);
  const pastedTechniqueIds = parseTechniqueIds(techniqueInput);
  const profileTechniqueIds = useMemo(
    () => sortedTechniqueIds([...selectedTechniqueIds, ...pastedTechniqueIds]),
    [pastedTechniqueIds, selectedTechniqueIds]
  );
  const unknownIds = unknownTechniqueIds(profileTechniqueIds, validTechniqueIds);
  const validProfileTechniqueIds = profileTechniqueIds.filter((techniqueId) => validTechniqueIds.has(techniqueId));
  const selectedProfile = profiles.find((profile) => profile.id === selectedProfileId) ?? null;
  const selectedProfileGroups = selectedProfile
    ? groupTechniquesByTactic(selectedProfile.technique_ids, techniqueLookup)
    : [];
  const selectedTactics = useMemo(
    () =>
      Array.from(new Set(techniques.map((technique) => technique.tactic))).sort((left, right) =>
        formatTactic(left).localeCompare(formatTactic(right))
      ),
    [techniques]
  );

  const filteredTechniques = useMemo(() => {
    const normalizedQuery = techniqueQuery.trim().toLowerCase();
    return techniques
      .filter((technique) => !profileTechniqueIds.includes(technique.technique_id))
      .filter((technique) => tacticFilter === "all" || technique.tactic === tacticFilter)
      .filter((technique) => {
        if (!normalizedQuery) {
          return true;
        }
        return (
          technique.technique_id.toLowerCase().includes(normalizedQuery) ||
          technique.name.toLowerCase().includes(normalizedQuery) ||
          technique.tactic.toLowerCase().includes(normalizedQuery)
        );
      })
      .slice(0, 90);
  }, [profileTechniqueIds, tacticFilter, techniqueQuery, techniques]);

  async function refreshProfiles(nextSelectedId?: string) {
    const nextProfiles = await getCustomSets();
    setProfiles(nextProfiles);
    setSelectedProfileId(nextSelectedId ?? nextProfiles[0]?.id ?? "");
  }

  async function handleSave() {
    setError(null);
    setNotice(null);

    if (unknownIds.length > 0) {
      setError(`Unknown technique IDs: ${unknownIds.join(", ")}`);
      return;
    }
    if (validProfileTechniqueIds.length === 0) {
      setError("Add at least one known ATT&CK technique before saving.");
      return;
    }

    setSaving(true);
    try {
      const savedProfile = await createCustomSet(
        profileName.trim() || "TTP Profile",
        validProfileTechniqueIds,
        description.trim() || undefined
      );
      await refreshProfiles(savedProfile.id);
      setNotice(`Saved ${savedProfile.name}.`);
    } catch (apiError) {
      setError(apiError instanceof Error ? apiError.message : "Unable to save profile");
    } finally {
      setSaving(false);
    }
  }

  async function handleCompareSaved() {
    setError(null);
    setNotice(null);
    setComparison(null);

    if (!selectedProfileId) {
      setError("Select or save a TTP profile before comparing.");
      return;
    }

    setComparing(true);
    try {
      setComparison(await compareCustomSet({ customSetId: selectedProfileId, metric, topN }));
    } catch (apiError) {
      setError(apiError instanceof Error ? apiError.message : "Unable to compare profile");
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
      const invalidIds = unknownTechniqueIds(importedIds, validTechniqueIds);
      const validIds = importedIds.filter((techniqueId) => validTechniqueIds.has(techniqueId));
      if (validIds.length === 0) {
        setError("Navigator layer did not contain techniques available in the loaded dataset.");
        return;
      }

      setSelectedTechniqueIds((currentIds) => sortedTechniqueIds([...currentIds, ...validIds]));
      if (typeof layer.name === "string" && layer.name.trim()) {
        setProfileName(layer.name.trim());
      }
      if (typeof layer.description === "string" && layer.description.trim()) {
        setDescription(layer.description.trim());
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

  function handleClearForm() {
    setProfileName("Observed TTP Profile");
    setDescription("");
    setTechniqueInput("");
    setSelectedTechniqueIds([]);
    setTechniqueQuery("");
    setTacticFilter("all");
    setNotice(null);
    setError(null);
  }

  return (
    <section className="comparison-workspace ttp-profile-workspace" aria-labelledby="ttp-profile-title">
      <div className="workspace-header">
        <div>
          <p className="eyebrow">TTP Profiles</p>
          <h1 id="ttp-profile-title">Build, save, and compare reusable profiles</h1>
        </div>
        <div className="source-pill">
          <Radar size={16} aria-hidden="true" />
          <span>{validProfileTechniqueIds.length} techniques</span>
        </div>
      </div>

      <div className="ttp-profile-layout">
        <form
          className="control-panel ttp-profile-form"
          onSubmit={(event) => {
            event.preventDefault();
            void handleSave();
          }}
        >
          <label className="field-group" htmlFor="ttp-profile-name">
            <span>Name</span>
            <input
              id="ttp-profile-name"
              value={profileName}
              onChange={(event) => {
                setProfileName(event.target.value);
              }}
            />
          </label>

          <label className="field-group" htmlFor="ttp-profile-description">
            <span>Description</span>
            <textarea
              id="ttp-profile-description"
              value={description}
              onChange={(event) => {
                setDescription(event.target.value);
              }}
              placeholder="Optional analyst notes or incident context"
              rows={3}
            />
          </label>

          <label className="field-group" htmlFor="ttp-profile-paste">
            <span>Paste technique IDs</span>
            <textarea
              id="ttp-profile-paste"
              value={techniqueInput}
              onChange={(event) => {
                setTechniqueInput(event.target.value);
              }}
              placeholder="T1059, T1105&#10;T1027"
              rows={5}
            />
          </label>

          <label className="field-group" htmlFor="ttp-profile-import">
            <span>Import Navigator layer</span>
            <div className="file-input-row">
              <Upload size={17} aria-hidden="true" />
              <input
                id="ttp-profile-import"
                type="file"
                accept="application/json,.json"
                onChange={(event) => {
                  void handleNavigatorImport(event.target.files?.[0]);
                  event.target.value = "";
                }}
              />
            </div>
          </label>

          <div className="split-controls">
            <label className="field-group" htmlFor="ttp-profile-tactic-filter">
              <span>Tactic</span>
              <select
                id="ttp-profile-tactic-filter"
                value={tacticFilter}
                onChange={(event) => {
                  setTacticFilter(event.target.value);
                }}
              >
                <option value="all">All tactics</option>
                {selectedTactics.map((tactic) => (
                  <option key={tactic} value={tactic}>
                    {formatTactic(tactic)}
                  </option>
                ))}
              </select>
            </label>

            <label className="field-group" htmlFor="ttp-profile-search">
              <span>Search</span>
              <div className="search-field">
                <Search size={17} aria-hidden="true" />
                <input
                  id="ttp-profile-search"
                  type="search"
                  value={techniqueQuery}
                  onChange={(event) => {
                    setTechniqueQuery(event.target.value);
                  }}
                  placeholder="T1059, PowerShell"
                />
              </div>
            </label>
          </div>

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
                <span>{technique.technique_id}</span>
                <small>
                  {technique.name} · {formatTactic(technique.tactic)}
                </small>
              </button>
            ))}
            {!loading && filteredTechniques.length === 0 ? <p className="muted">No matching techniques</p> : null}
          </div>

          <SelectedTechniqueSummary
            techniqueIds={validProfileTechniqueIds}
            unknownIds={unknownIds}
            lookup={techniqueLookup}
            onRemove={(techniqueId) => {
              setSelectedTechniqueIds((currentIds) => currentIds.filter((id) => id !== techniqueId));
              setTechniqueInput(sortedTechniqueIds(parseTechniqueIds(techniqueInput).filter((id) => id !== techniqueId)).join("\n"));
            }}
          />

          <div className="action-row">
            <button className="secondary-action" type="button" onClick={handleClearForm}>
              <X size={17} aria-hidden="true" />
              <span>Clear form</span>
            </button>
            <button className="primary-action" type="submit" disabled={saving || loading}>
              {saving ? <Loader2 className="spin" size={17} aria-hidden="true" /> : <Save size={17} aria-hidden="true" />}
              <span>{saving ? "Saving" : "Save profile"}</span>
            </button>
          </div>

          {loading ? <StatusMessage tone="neutral" message="Loading profiles and techniques" /> : null}
          {notice ? <StatusMessage tone="neutral" message={notice} /> : null}
          {error ? <StatusMessage tone="error" message={error} /> : null}
        </form>

        <section className="control-panel saved-profile-panel" aria-label="Saved TTP profiles">
          <div className="mini-header">
            <strong>Saved profiles</strong>
            <span>{profiles.length}</span>
          </div>
          <label className="field-group" htmlFor="saved-profile-select">
            <span>Profile</span>
            <select
              id="saved-profile-select"
              value={selectedProfileId}
              disabled={profiles.length === 0}
              onChange={(event) => {
                setSelectedProfileId(event.target.value);
              }}
            >
              {profiles.map((profile) => (
                <option key={profile.id} value={profile.id}>
                  {profile.name} ({profile.technique_ids.length})
                </option>
              ))}
            </select>
          </label>

          <div className="split-controls">
            <label className="field-group" htmlFor="profile-metric-select">
              <span>Metric</span>
              <select
                id="profile-metric-select"
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

            <label className="field-group" htmlFor="profile-top-n-input">
              <span>Results</span>
              <input
                id="profile-top-n-input"
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

          <button
            className="primary-action"
            type="button"
            disabled={!selectedProfileId || comparing}
            onClick={() => void handleCompareSaved()}
          >
            {comparing ? <Loader2 className="spin" size={17} aria-hidden="true" /> : <Plus size={17} aria-hidden="true" />}
            <span>{comparing ? "Comparing" : "Compare profile"}</span>
          </button>

          {selectedProfile ? (
            <>
              <button className="secondary-action" type="button" onClick={() => downloadProfileNavigator(selectedProfile)}>
                <Download size={17} aria-hidden="true" />
                <span>Export Navigator</span>
              </button>
              <ProfileInspector profile={selectedProfile} groups={selectedProfileGroups} />
            </>
          ) : (
            <div className="empty-state compact-empty">
              <FileJson size={24} aria-hidden="true" />
              <p>Save a TTP profile to inspect and compare it.</p>
            </div>
          )}
        </section>

        <ProfileComparisonResults comparison={comparison} loading={comparing} topN={topN} />
      </div>
    </section>
  );
}

function SelectedTechniqueSummary({
  techniqueIds,
  unknownIds,
  lookup,
  onRemove
}: {
  techniqueIds: string[];
  unknownIds: string[];
  lookup: Map<string, TechniqueListItem>;
  onRemove: (techniqueId: string) => void;
}) {
  const selectedTechniques = techniqueIds.map((techniqueId) => lookup.get(techniqueId)).filter(Boolean) as TechniqueListItem[];

  return (
    <div className="selected-techniques">
      <div className="mini-header">
        <strong>{techniqueIds.length} known selected</strong>
        {unknownIds.length > 0 ? <span className="error-text">{unknownIds.length} unknown</span> : null}
      </div>
      <div className="chip-list">
        {selectedTechniques.map((technique) => (
          <button
            className="technique-chip"
            key={technique.technique_id}
            type="button"
            title={technique.name}
            onClick={() => onRemove(technique.technique_id)}
          >
            <span>{technique.technique_id}</span>
            <X size={14} aria-hidden="true" />
          </button>
        ))}
        {unknownIds.map((techniqueId) => (
          <span className="technique-chip unknown-chip" key={techniqueId}>
            {techniqueId}
          </span>
        ))}
      </div>
    </div>
  );
}

function ProfileInspector({ profile, groups }: { profile: CustomTTPSet; groups: ReturnType<typeof groupTechniquesByTactic> }) {
  return (
    <div className="profile-inspector">
      <div>
        <p className="panel-label">Selected profile</p>
        <h2>{profile.name}</h2>
        <p>{profile.description || "No description provided."}</p>
      </div>
      <div className="result-meta">
        <span>{profile.technique_ids.length} techniques</span>
        <span>Updated {formatDate(profile.updated_at)}</span>
      </div>
      <div className="profile-technique-groups">
        {groups.length === 0 ? <p className="muted">No matching technique metadata is loaded.</p> : null}
        {groups.map((group) => (
          <div className="profile-technique-group" key={group.tactic}>
            <strong>{formatTactic(group.tactic)}</strong>
            <ul>
              {group.techniques.map((technique) => (
                <li key={technique.technique_id}>
                  <span>{technique.technique_id}</span>
                  {technique.name}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

function ProfileComparisonResults({
  comparison,
  loading,
  topN
}: {
  comparison: ActorComparisonResponse | null;
  loading: boolean;
  topN: number;
}) {
  if (loading) {
    return (
      <section className="results-panel profile-results" aria-live="polite">
        <div className="empty-state">
          <Loader2 className="spin" size={22} aria-hidden="true" />
          <p>Comparing TTP profile</p>
        </div>
      </section>
    );
  }

  if (!comparison) {
    return (
      <section className="results-panel profile-results">
        <div className="empty-state">
          <Radar size={24} aria-hidden="true" />
          <p>Select a saved profile and compare it against actors.</p>
        </div>
      </section>
    );
  }

  const canExport = comparison.results.length > 0;

  return (
    <section className="results-panel profile-results" aria-live="polite">
      <div className="results-header">
        <div>
          <p className="panel-label">TTP profile</p>
          <h2>{comparison.input_name}</h2>
        </div>
        <div className="results-actions">
          <span className="metric-label">{metricLabel(comparison.metric)}</span>
          <button
            type="button"
            title={canExport ? "Export JSON" : "Run a comparison with results before exporting"}
            disabled={!canExport}
            onClick={() => downloadComparisonExport(comparison, "json", "mitre", topN)}
          >
            <FileJson size={16} aria-hidden="true" />
          </button>
          <button
            type="button"
            title={canExport ? "Export CSV" : "Run a comparison with results before exporting"}
            disabled={!canExport}
            onClick={() => downloadComparisonExport(comparison, "csv", "mitre", topN)}
          >
            <Table size={16} aria-hidden="true" />
          </button>
          <button
            type="button"
            title={canExport ? "Export Navigator layer" : "Run a comparison with results before exporting"}
            disabled={!canExport}
            onClick={() => downloadComparisonExport(comparison, "navigator", "mitre", topN)}
          >
            <Download size={16} aria-hidden="true" />
          </button>
        </div>
      </div>
      <ol className="result-list">
        {comparison.results.length === 0 ? (
          <li className="empty-result">No comparable actors found. Load MITRE data before comparing profiles.</li>
        ) : null}
        {comparison.results.map((result, index) => (
          <li className="result-row incident-result-row" key={result.matched_entity_id}>
            <div className="rank">{index + 1}</div>
            <div className="result-main">
              <div className="result-title-line">
                <h3>{result.matched_entity_name}</h3>
                <strong>{formatScore(result.score)}</strong>
              </div>
              <div className="result-meta">
                <span>{result.shared_techniques.length} shared techniques</span>
                <span>{result.unique_to_input.length} unmatched profile</span>
                <span>{result.unique_to_matched_entity.length} actor-only techniques</span>
              </div>
              <WhyMatched result={result} />
              <TacticBreakdownList items={result.tactic_breakdown} />
              <SoftwarePreview software={result.shared_software} />
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

function WhyMatched({ result }: { result: ActorComparisonResponse["results"][number] }) {
  const rareShared = result.rare_shared_techniques ?? [];
  return (
    <div className="why-match">
      <strong>Why this matched</strong>
      <p>
        Technique overlap score {formatScore(result.technique_score)}
        {result.software_score > 0 ? `, software overlap ${formatScore(result.software_score)}` : ""}.
      </p>
      <TechniqueLine label="Shared techniques" techniques={result.shared_techniques} emptyText="No shared techniques" />
      {rareShared.length > 0 ? <TechniqueLine label="Rare shared techniques" techniques={rareShared} emptyText="" /> : null}
    </div>
  );
}

function TechniqueLine({ label, techniques, emptyText }: { label: string; techniques: string[]; emptyText: string }) {
  const visible = techniques.slice(0, 12);
  const hiddenCount = techniques.length - visible.length;
  return (
    <p className="technique-preview">
      <strong>{label}</strong> {visible.join(", ") || emptyText}
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

function TacticBreakdownList({ items }: { items: TacticBreakdown[] }) {
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
            {item.shared_techniques.length > 0 ? `: ${item.shared_techniques.slice(0, 5).join(", ")}` : ""}
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

function downloadProfileNavigator(profile: CustomTTPSet) {
  const payload = {
    version: "4.5",
    name: profile.name,
    domain: "enterprise-attack",
    description: profile.description ?? "TTP profile exported from WhoIsWhoAPT.",
    techniques: profile.technique_ids.map((techniqueID) => ({
      techniqueID,
      enabled: true
    }))
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${safeFilename(profile.name)}-navigator.json`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
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

function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

function safeFilename(value: string): string {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "ttp-profile"
  );
}
