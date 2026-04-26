import { AlertCircle, Download, FileJson, Loader2, Radar, Save, Search, Upload, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { createTTPProfile, getActorDetail, getActors, getTechniques, getTTPProfiles } from "../api/client";
import {
  buildComparableProfiles,
  filterComparableProfiles,
  groupComparableProfiles,
  profileDetail,
  profileKey,
  profileTechniqueIds,
  profileTypeLabel,
  type ComparableProfile
} from "../api/profileLibraryUtils";
import {
  extractNavigatorTechniqueIds,
  formatTactic,
  groupTechniquesByTactic,
  parseTechniqueIds,
  techniqueLabel,
  techniqueLookupFromList,
  techniqueTitle,
  type NavigatorLayer,
  type TechniqueLookup,
  unknownTechniqueIds
} from "../api/ttpProfileUtils";
import type { ActorDetail, ActorListItem, SoftwareSummary, TechniqueListItem, TTPProfile } from "../api/types";

export function TTPProfilesPanel() {
  const [actors, setActors] = useState<ActorListItem[]>([]);
  const [customProfiles, setCustomProfiles] = useState<TTPProfile[]>([]);
  const [techniques, setTechniques] = useState<TechniqueListItem[]>([]);
  const [actorDetails, setActorDetails] = useState<Record<string, ActorDetail>>({});
  const requestedActorDetailIds = useRef(new Set<string>());
  const [failedActorDetailIds, setFailedActorDetailIds] = useState<Set<string>>(() => new Set());
  const [selectedProfileKey, setSelectedProfileKey] = useState("");
  const [libraryQuery, setLibraryQuery] = useState("");
  const [profileName, setProfileName] = useState("Observed TTP Profile");
  const [description, setDescription] = useState("");
  const [techniqueInput, setTechniqueInput] = useState("");
  const [selectedTechniqueIds, setSelectedTechniqueIds] = useState<string[]>([]);
  const [techniqueQuery, setTechniqueQuery] = useState("");
  const [tacticFilter, setTacticFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([getActors(), getTTPProfiles(), getTechniques()])
      .then(([actorItems, customProfileItems, techniqueItems]) => {
        setActors(actorItems);
        setCustomProfiles(customProfileItems);
        setTechniques(techniqueItems);
        const firstProfile = buildComparableProfiles(actorItems, customProfileItems)[0];
        setSelectedProfileKey(firstProfile?.key ?? "");
      })
      .catch((apiError: unknown) => {
        setError(apiError instanceof Error ? apiError.message : "Unable to load TTP profile library");
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  const techniqueLookup = useMemo(() => techniqueLookupFromList(techniques), [techniques]);
  const validTechniqueIds = useMemo(() => new Set(techniques.map((technique) => technique.technique_id)), [techniques]);
  const pastedTechniqueIds = parseTechniqueIds(techniqueInput);
  const draftTechniqueIds = useMemo(
    () => sortedTechniqueIds([...selectedTechniqueIds, ...pastedTechniqueIds]),
    [pastedTechniqueIds, selectedTechniqueIds]
  );
  const unknownIds = unknownTechniqueIds(draftTechniqueIds, validTechniqueIds);
  const validDraftTechniqueIds = draftTechniqueIds.filter((techniqueId) => validTechniqueIds.has(techniqueId));
  const comparableProfiles = useMemo(() => buildComparableProfiles(actors, customProfiles), [actors, customProfiles]);
  const filteredProfiles = useMemo(
    () => filterComparableProfiles(comparableProfiles, libraryQuery),
    [comparableProfiles, libraryQuery]
  );
  const selectedProfile = comparableProfiles.find((profile) => profile.key === selectedProfileKey) ?? comparableProfiles[0] ?? null;
  const selectedActorDetail =
    selectedProfile?.type === "actor" ? actorDetails[selectedProfile.id] ?? null : null;
  const selectedCustomProfile =
    selectedProfile?.type === "custom" ? customProfiles.find((profile) => profile.id === selectedProfile.id) ?? null : null;
  const selectedProfileTechniqueIds = selectedProfile ? profileTechniqueIds(selectedProfile, selectedActorDetail) : [];
  const selectedProfileGroups = groupTechniquesByTactic(selectedProfileTechniqueIds, techniqueLookup);
  const detailLoading = Boolean(
      selectedProfile?.type === "actor" &&
      !selectedActorDetail &&
      !failedActorDetailIds.has(selectedProfile.id)
  );
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
      .filter((technique) => !draftTechniqueIds.includes(technique.technique_id))
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
  }, [draftTechniqueIds, tacticFilter, techniqueQuery, techniques]);

  useEffect(() => {
    if (
      !selectedProfile ||
      selectedProfile.type !== "actor" ||
      actorDetails[selectedProfile.id] ||
      requestedActorDetailIds.current.has(selectedProfile.id)
    ) {
      return;
    }

    requestedActorDetailIds.current.add(selectedProfile.id);
    getActorDetail(selectedProfile.id)
      .then((detail) => {
        setActorDetails((currentDetails) => ({ ...currentDetails, [detail.id]: detail }));
      })
      .catch((apiError: unknown) => {
        setFailedActorDetailIds((currentIds) => new Set([...currentIds, selectedProfile.id]));
        setError(apiError instanceof Error ? apiError.message : "Unable to load actor profile details");
      });
  }, [actorDetails, selectedProfile]);

  async function refreshCustomProfiles(nextSelectedId?: string) {
    const nextProfiles = await getTTPProfiles();
    setCustomProfiles(nextProfiles);
    if (nextSelectedId) {
      setSelectedProfileKey(profileKey("custom", nextSelectedId));
    } else if (!selectedProfileKey && nextProfiles[0]) {
      setSelectedProfileKey(profileKey("custom", nextProfiles[0].id));
    }
  }

  async function handleSave() {
    setError(null);
    setNotice(null);

    if (unknownIds.length > 0) {
      setError(`Unknown technique IDs: ${unknownIds.join(", ")}`);
      return;
    }
    if (validDraftTechniqueIds.length === 0) {
      setError("Add at least one known ATT&CK technique before saving.");
      return;
    }

    setSaving(true);
    try {
      const savedProfile = await createTTPProfile(
        profileName.trim() || "TTP Profile",
        validDraftTechniqueIds,
        description.trim() || undefined
      );
      await refreshCustomProfiles(savedProfile.id);
      setNotice(`Saved ${savedProfile.name}.`);
    } catch (apiError) {
      setError(apiError instanceof Error ? apiError.message : "Unable to save TTP profile");
    } finally {
      setSaving(false);
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
        setError("Navigator layer did not contain known techniques from the loaded dataset.");
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
          <h1 id="ttp-profile-title">TTP profile library</h1>
        </div>
        <div className="source-pill">
          <Radar size={16} aria-hidden="true" />
          <span>{comparableProfiles.length} comparable profiles</span>
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
          <div className="mini-header">
            <strong>Create Custom TTP Profile</strong>
            <span>{validDraftTechniqueIds.length} techniques</span>
          </div>

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
              placeholder="Optional analyst notes or source context"
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
            <span>Import Navigator profile</span>
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
                  {technique.name} - {formatTactic(technique.tactic)}
                </small>
              </button>
            ))}
            {!loading && filteredTechniques.length === 0 ? <p className="muted">No matching techniques</p> : null}
          </div>

          <SelectedTechniqueSummary
            techniqueIds={validDraftTechniqueIds}
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
            <button className="primary-action" type="submit" disabled={saving || loading || validDraftTechniqueIds.length === 0}>
              {saving ? <Loader2 className="spin" size={17} aria-hidden="true" /> : <Save size={17} aria-hidden="true" />}
              <span>{saving ? "Saving" : "Save profile"}</span>
            </button>
          </div>

          {loading ? <StatusMessage tone="neutral" message="Loading TTP profile library" /> : null}
          {notice ? <StatusMessage tone="neutral" message={notice} /> : null}
          {error ? <StatusMessage tone="error" message={error} /> : null}
        </form>

        <section className="control-panel saved-profile-panel" aria-label="TTP profile library">
          <div className="mini-header">
            <strong>Profile Library</strong>
            <span>{filteredProfiles.length}/{comparableProfiles.length}</span>
          </div>

          <label className="field-group" htmlFor="profile-library-search">
            <span>Search library</span>
            <div className="search-field">
              <Search size={17} aria-hidden="true" />
              <input
                id="profile-library-search"
                type="search"
                value={libraryQuery}
                onChange={(event) => {
                  setLibraryQuery(event.target.value);
                }}
                placeholder="Profile name, actor alias"
              />
            </div>
          </label>

          <ProfileLibraryList
            profiles={filteredProfiles}
            selectedKey={selectedProfile?.key ?? ""}
            onSelect={(profile) => {
              setSelectedProfileKey(profile.key);
              setError(null);
            }}
          />
        </section>

        <ProfileInspector
          profile={selectedProfile}
          customProfile={selectedCustomProfile}
          actorDetail={selectedActorDetail}
          detailLoading={detailLoading}
          groups={selectedProfileGroups}
          techniqueIds={selectedProfileTechniqueIds}
          techniqueLookup={techniqueLookup}
        />
      </div>
    </section>
  );
}

function ProfileLibraryList({
  profiles,
  selectedKey,
  onSelect
}: {
  profiles: ComparableProfile[];
  selectedKey: string;
  onSelect: (profile: ComparableProfile) => void;
}) {
  const groups = groupComparableProfiles(profiles);

  return (
    <div className="profile-library-list">
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
                className={`technique-option target-option ${profile.key === selectedKey ? "selected-option" : ""}`}
                key={profile.key}
                type="button"
                onClick={() => onSelect(profile)}
              >
                <span>{profile.name}</span>
                <small>{profileDetail(profile)}</small>
              </button>
            ))}
          </div>
        </div>
      ))}
    </div>
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
  lookup: TechniqueLookup;
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
            title={techniqueTitle(technique.technique_id, lookup)}
            onClick={() => onRemove(technique.technique_id)}
          >
            <span>{techniqueLabel(technique.technique_id, lookup)}</span>
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

function ProfileInspector({
  profile,
  customProfile,
  actorDetail,
  detailLoading,
  groups,
  techniqueIds,
  techniqueLookup
}: {
  profile: ComparableProfile | null;
  customProfile: TTPProfile | null;
  actorDetail: ActorDetail | null;
  detailLoading: boolean;
  groups: ReturnType<typeof groupTechniquesByTactic>;
  techniqueIds: string[];
  techniqueLookup: TechniqueLookup;
}) {
  if (!profile) {
    return (
      <section className="results-panel profile-results">
        <div className="empty-state">
          <FileJson size={24} aria-hidden="true" />
          <p>Select a profile from the library.</p>
        </div>
      </section>
    );
  }

  const description = actorDetail?.description ?? customProfile?.description ?? profile.description;
  const canExport = techniqueIds.length > 0;

  return (
    <section className="results-panel profile-results" aria-live="polite">
      <div className="results-header">
        <div>
          <p className="panel-label">{profileTypeLabel(profile.type)}</p>
          <h2>{profile.name}</h2>
          <p className="scope-summary">{description || "No description provided."}</p>
        </div>
        <div className="results-actions">
          <span className="metric-label">{techniqueIds.length || profile.technique_count} techniques</span>
          <button
            type="button"
            title={canExport ? "Export Navigator profile" : "Technique details are still loading"}
            disabled={!canExport}
            onClick={() => downloadProfileNavigator(profile.name, description, techniqueIds)}
          >
            <Download size={16} aria-hidden="true" />
          </button>
        </div>
      </div>

      <div className="profile-inspector library-inspector">
        <div className="result-meta">
          <span>Type: {profileTypeLabel(profile.type)}</span>
          <span>{profile.technique_count} listed techniques</span>
          {customProfile ? <span>Updated {formatDate(customProfile.updated_at)}</span> : null}
        </div>

        {detailLoading ? (
          <div className="empty-state compact-empty">
            <Loader2 className="spin" size={22} aria-hidden="true" />
            <p>Loading actor profile details</p>
          </div>
        ) : null}

        {actorDetail ? <SoftwareList software={actorDetail.software_used} /> : null}

        <div className="profile-technique-groups">
          {groups.length === 0 ? <p className="muted">No techniques available.</p> : null}
          {groups.map((group) => (
            <div className="profile-technique-group" key={group.tactic}>
              <strong>{formatTactic(group.tactic)}</strong>
              <ul>
                {group.techniques.map((technique) => (
                  <li key={technique.technique_id}>
                    <span title={techniqueTitle(technique.technique_id, techniqueLookup)}>
                      {techniqueLabel(technique.technique_id, techniqueLookup)}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function SoftwareList({ software }: { software: SoftwareSummary[] }) {
  if (software.length === 0) {
    return (
      <div className="why-match">
        <strong>Software</strong>
        <p>No software available for this actor profile.</p>
      </div>
    );
  }

  return (
    <div className="why-match">
      <strong>Software</strong>
      <div className="chip-list">
        {software.slice(0, 18).map((item) => (
          <span className="technique-chip unknown-chip" key={item.id}>
            {item.name}
          </span>
        ))}
      </div>
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

function downloadProfileNavigator(name: string, description: string | null | undefined, techniqueIds: string[]) {
  const payload = {
    version: "4.5",
    name,
    domain: "enterprise-attack",
    description: description ?? "TTP profile exported from WhoIsWhoAPT.",
    techniques: techniqueIds.map((techniqueID) => ({
      techniqueID,
      enabled: true
    }))
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${safeFilename(name)}-navigator.json`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function sortedTechniqueIds(techniqueIds: string[]): string[] {
  return Array.from(new Set(techniqueIds)).sort((left, right) => left.localeCompare(right));
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
