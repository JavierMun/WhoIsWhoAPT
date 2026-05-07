import { AlertCircle, Download, Edit, FileJson, Loader2, Plus, Radar, Save, Search, Trash2, Upload, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import {
  createTTPProfile,
  deleteTTPProfile,
  getActorDetail,
  getActors,
  getTechniques,
  getTTPProfiles,
  updateTTPProfile
} from "../api/client";
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
import type { ActorDetail, ActorListItem, PrimarySourceName, SoftwareSummary, TechniqueListItem, TTPProfile } from "../api/types";
import { OpenCTIReportImporter } from "./OpenCTIReportImporter";

type FormMode = "hidden" | "create" | "edit";

export function TTPProfilesPanel({ activeSource = "mitre" }: { activeSource?: PrimarySourceName }) {
  const [actors, setActors] = useState<ActorListItem[]>([]);
  const [customProfiles, setCustomProfiles] = useState<TTPProfile[]>([]);
  const [techniques, setTechniques] = useState<TechniqueListItem[]>([]);
  const [actorDetails, setActorDetails] = useState<Record<string, ActorDetail>>({});
  const requestedActorDetailIds = useRef(new Set<string>());
  const [failedActorDetailIds, setFailedActorDetailIds] = useState<Set<string>>(() => new Set());
  const [selectedProfileKey, setSelectedProfileKey] = useState("");
  const [formMode, setFormMode] = useState<FormMode>("hidden");
  const [editingProfileId, setEditingProfileId] = useState<string | null>(null);
  const [libraryQuery, setLibraryQuery] = useState("");
  const [profileName, setProfileName] = useState("Observed TTP Profile");
  const [description, setDescription] = useState("");
  const [targetSectors, setTargetSectors] = useState("");
  const [targetCountries, setTargetCountries] = useState("");
  const [cvesExploited, setCvesExploited] = useState("");
  const [motivation, setMotivation] = useState("");
  const [techniqueInput, setTechniqueInput] = useState("");
  const [selectedTechniqueIds, setSelectedTechniqueIds] = useState<string[]>([]);
  const [techniqueQuery, setTechniqueQuery] = useState("");
  const [tacticFilter, setTacticFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
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

  function _resetEnrichment() {
    setTargetSectors("");
    setTargetCountries("");
    setCvesExploited("");
    setMotivation("");
  }

  function openCreateForm() {
    setFormMode("create");
    setEditingProfileId(null);
    setProfileName("Observed TTP Profile");
    setDescription("");
    _resetEnrichment();
    setTechniqueInput("");
    setSelectedTechniqueIds([]);
    setTechniqueQuery("");
    setTacticFilter("all");
    setNotice(null);
    setError(null);
  }

  function handleReportImport(reportName: string, importedIds: string[]) {
    const validIds = importedIds.filter((id) => validTechniqueIds.has(id));
    setFormMode("create");
    setEditingProfileId(null);
    setProfileName(reportName);
    setDescription("");
    setTechniqueInput("");
    setSelectedTechniqueIds(sortedTechniqueIds(validIds));
    setTechniqueQuery("");
    setTacticFilter("all");
    setNotice(
      validIds.length < importedIds.length
        ? `${importedIds.length - validIds.length} technique(s) from the report were not found in the current dataset and were skipped.`
        : null
    );
    setError(null);
  }

  function openEditForm(profile: TTPProfile) {
    setFormMode("edit");
    setEditingProfileId(profile.id);
    setProfileName(profile.name);
    setDescription(profile.description ?? "");
    setTargetSectors((profile.target_sectors ?? []).join(", "));
    setTargetCountries((profile.target_countries ?? []).join(", "));
    setCvesExploited((profile.cves_exploited ?? []).join(", "));
    setMotivation(profile.motivation ?? "");
    setTechniqueInput("");
    setSelectedTechniqueIds(sortedTechniqueIds(profile.technique_ids));
    setTechniqueQuery("");
    setTacticFilter("all");
    setNotice(null);
    setError(null);
  }

  function closeForm() {
    setFormMode("hidden");
    setEditingProfileId(null);
    setTechniqueQuery("");
    setTacticFilter("all");
    setNotice(null);
    setError(null);
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
      const splitTags = (raw: string) =>
        raw.split(",").map((s) => s.trim()).filter(Boolean);

      const payload = {
        name: profileName.trim() || "TTP Profile",
        description: description.trim() || undefined,
        techniqueIds: validDraftTechniqueIds,
        targetSectors: splitTags(targetSectors),
        targetCountries: splitTags(targetCountries),
        cvesExploited: splitTags(cvesExploited),
        motivation: motivation.trim() || undefined
      };

      if (formMode === "edit" && editingProfileId) {
        const updatedProfile = await updateTTPProfile(editingProfileId, payload);
        await refreshCustomProfiles(updatedProfile.id);
        setNotice(`Saved changes to ${updatedProfile.name}.`);
      } else {
        const savedProfile = await createTTPProfile(payload);
        await refreshCustomProfiles(savedProfile.id);
        setNotice(`Saved ${savedProfile.name}.`);
      }
      setFormMode("hidden");
      setEditingProfileId(null);
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

  async function handleDelete(profile: TTPProfile) {
    if (!window.confirm(`Delete "${profile.name}"? This cannot be undone.`)) {
      return;
    }

    setDeleting(true);
    setError(null);
    setNotice(null);
    try {
      await deleteTTPProfile(profile.id);
      const nextProfiles = await getTTPProfiles();
      setCustomProfiles(nextProfiles);
      const nextComparableProfiles = buildComparableProfiles(actors, nextProfiles);
      setSelectedProfileKey(nextComparableProfiles[0]?.key ?? "");
      if (editingProfileId === profile.id) {
        closeForm();
      }
      setNotice(`Deleted ${profile.name}.`);
    } catch (apiError) {
      setError(apiError instanceof Error ? apiError.message : "Unable to delete TTP profile");
    } finally {
      setDeleting(false);
    }
  }

  function handleClearForm() {
    setProfileName("Observed TTP Profile");
    setDescription("");
    _resetEnrichment();
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

      <div className={`ttp-profile-layout ${formMode === "hidden" ? "library-first-layout" : ""}`}>
        <section className="control-panel saved-profile-panel" aria-label="TTP profile library">
          <div className="mini-header">
            <strong>Profile Library</strong>
            <span>{filteredProfiles.length}/{comparableProfiles.length}</span>
          </div>

          <button className="primary-action" type="button" onClick={openCreateForm}>
            <Plus size={17} aria-hidden="true" />
            <span>New Custom Profile</span>
          </button>

          {activeSource === "opencti" ? (
            <OpenCTIReportImporter onImport={handleReportImport} />
          ) : null}

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
          {loading ? <StatusMessage tone="neutral" message="Loading TTP profile library" /> : null}
          {formMode === "hidden" && notice ? <StatusMessage tone="neutral" message={notice} /> : null}
          {formMode === "hidden" && error ? <StatusMessage tone="error" message={error} /> : null}
        </section>

        <ProfileInspector
          profile={selectedProfile}
          customProfile={selectedCustomProfile}
          actorDetail={selectedActorDetail}
          detailLoading={detailLoading}
          deleting={deleting}
          groups={selectedProfileGroups}
          techniqueIds={selectedProfileTechniqueIds}
          techniqueLookup={techniqueLookup}
          onEdit={openEditForm}
          onDelete={(profile) => void handleDelete(profile)}
        />

        {formMode !== "hidden" ? (
          <ProfileForm
            mode={formMode}
            profileName={profileName}
            description={description}
            techniqueInput={techniqueInput}
            selectedTechniqueIds={validDraftTechniqueIds}
            unknownIds={unknownIds}
            techniqueLookup={techniqueLookup}
            techniqueQuery={techniqueQuery}
            tacticFilter={tacticFilter}
            selectedTactics={selectedTactics}
            filteredTechniques={filteredTechniques}
            loading={loading}
            saving={saving}
            notice={notice}
            error={error}
            targetSectors={targetSectors}
            targetCountries={targetCountries}
            cvesExploited={cvesExploited}
            motivation={motivation}
            onNameChange={setProfileName}
            onDescriptionChange={setDescription}
            onTargetSectorsChange={setTargetSectors}
            onTargetCountriesChange={setTargetCountries}
            onCvesExploitedChange={setCvesExploited}
            onMotivationChange={setMotivation}
            onTechniqueInputChange={setTechniqueInput}
            onTacticFilterChange={setTacticFilter}
            onTechniqueQueryChange={setTechniqueQuery}
            onNavigatorImport={(file) => void handleNavigatorImport(file)}
            onAddTechnique={(techniqueId) => {
              setSelectedTechniqueIds((currentIds) => sortedTechniqueIds([...currentIds, techniqueId]));
            }}
            onRemoveTechnique={(techniqueId) => {
              setSelectedTechniqueIds((currentIds) => currentIds.filter((id) => id !== techniqueId));
              setTechniqueInput(sortedTechniqueIds(parseTechniqueIds(techniqueInput).filter((id) => id !== techniqueId)).join("\n"));
            }}
            onClear={handleClearForm}
            onCancel={closeForm}
            onSubmit={() => void handleSave()}
          />
        ) : null}
      </div>
    </section>
  );
}

function ProfileForm({
  mode,
  profileName,
  description,
  targetSectors,
  targetCountries,
  cvesExploited,
  motivation,
  techniqueInput,
  selectedTechniqueIds,
  unknownIds,
  techniqueLookup,
  techniqueQuery,
  tacticFilter,
  selectedTactics,
  filteredTechniques,
  loading,
  saving,
  notice,
  error,
  onNameChange,
  onDescriptionChange,
  onTargetSectorsChange,
  onTargetCountriesChange,
  onCvesExploitedChange,
  onMotivationChange,
  onTechniqueInputChange,
  onTacticFilterChange,
  onTechniqueQueryChange,
  onNavigatorImport,
  onAddTechnique,
  onRemoveTechnique,
  onClear,
  onCancel,
  onSubmit
}: {
  mode: Exclude<FormMode, "hidden">;
  profileName: string;
  description: string;
  targetSectors: string;
  targetCountries: string;
  cvesExploited: string;
  motivation: string;
  techniqueInput: string;
  selectedTechniqueIds: string[];
  unknownIds: string[];
  techniqueLookup: TechniqueLookup;
  techniqueQuery: string;
  tacticFilter: string;
  selectedTactics: string[];
  filteredTechniques: TechniqueListItem[];
  loading: boolean;
  saving: boolean;
  notice: string | null;
  error: string | null;
  onNameChange: (value: string) => void;
  onDescriptionChange: (value: string) => void;
  onTargetSectorsChange: (value: string) => void;
  onTargetCountriesChange: (value: string) => void;
  onCvesExploitedChange: (value: string) => void;
  onMotivationChange: (value: string) => void;
  onTechniqueInputChange: (value: string) => void;
  onTacticFilterChange: (value: string) => void;
  onTechniqueQueryChange: (value: string) => void;
  onNavigatorImport: (file: File | undefined) => void;
  onAddTechnique: (techniqueId: string) => void;
  onRemoveTechnique: (techniqueId: string) => void;
  onClear: () => void;
  onCancel: () => void;
  onSubmit: () => void;
}) {
  return (
    <form
      className="control-panel ttp-profile-form"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit();
      }}
    >
      <div className="mini-header">
        <strong>{mode === "edit" ? "Edit Custom TTP Profile" : "Create Custom TTP Profile"}</strong>
        <span>{selectedTechniqueIds.length} techniques</span>
      </div>

      <label className="field-group" htmlFor="ttp-profile-name">
        <span>Name</span>
        <input
          id="ttp-profile-name"
          value={profileName}
          onChange={(event) => {
            onNameChange(event.target.value);
          }}
        />
      </label>

      <label className="field-group" htmlFor="ttp-profile-description">
        <span>Description</span>
        <textarea
          id="ttp-profile-description"
          value={description}
          onChange={(event) => {
            onDescriptionChange(event.target.value);
          }}
          placeholder="Optional analyst notes or source context"
          rows={3}
        />
      </label>

      <div className="profile-enrichment-fields">
        <label className="field-group" htmlFor="ttp-profile-sectors">
          <span>Target sectors <span className="field-hint-inline">(comma-separated)</span></span>
          <input
            id="ttp-profile-sectors"
            type="text"
            value={targetSectors}
            onChange={(e) => onTargetSectorsChange(e.target.value)}
            placeholder="Government, Energy, Finance"
          />
        </label>
        <label className="field-group" htmlFor="ttp-profile-countries">
          <span>Target countries <span className="field-hint-inline">(comma-separated)</span></span>
          <input
            id="ttp-profile-countries"
            type="text"
            value={targetCountries}
            onChange={(e) => onTargetCountriesChange(e.target.value)}
            placeholder="Iran, Russia, United States"
          />
        </label>
        <label className="field-group" htmlFor="ttp-profile-cves">
          <span>CVEs exploited <span className="field-hint-inline">(comma-separated)</span></span>
          <input
            id="ttp-profile-cves"
            type="text"
            value={cvesExploited}
            onChange={(e) => onCvesExploitedChange(e.target.value)}
            placeholder="CVE-2023-1234, CVE-2024-5678"
          />
        </label>
        <label className="field-group" htmlFor="ttp-profile-motivation">
          <span>Motivation</span>
          <input
            id="ttp-profile-motivation"
            type="text"
            value={motivation}
            onChange={(e) => onMotivationChange(e.target.value)}
            placeholder="Espionage, Financial gain, Disruption…"
          />
        </label>
      </div>

      <label className="field-group" htmlFor="ttp-profile-paste">
        <span>Paste technique IDs</span>
        <textarea
          id="ttp-profile-paste"
          value={techniqueInput}
          onChange={(event) => {
            onTechniqueInputChange(event.target.value);
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
              onNavigatorImport(event.target.files?.[0]);
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
              onTacticFilterChange(event.target.value);
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
                onTechniqueQueryChange(event.target.value);
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
            onClick={() => onAddTechnique(technique.technique_id)}
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
        techniqueIds={selectedTechniqueIds}
        unknownIds={unknownIds}
        lookup={techniqueLookup}
        onRemove={onRemoveTechnique}
      />

      <div className="action-row">
        <button className="secondary-action" type="button" onClick={onCancel}>
          <X size={17} aria-hidden="true" />
          <span>Cancel</span>
        </button>
        {mode === "create" ? (
          <button className="secondary-action" type="button" onClick={onClear}>
            <X size={17} aria-hidden="true" />
            <span>Clear form</span>
          </button>
        ) : null}
        <button className="primary-action" type="submit" disabled={saving || loading || selectedTechniqueIds.length === 0}>
          {saving ? <Loader2 className="spin" size={17} aria-hidden="true" /> : <Save size={17} aria-hidden="true" />}
          <span>{saving ? "Saving" : mode === "edit" ? "Save changes" : "Save profile"}</span>
        </button>
      </div>

      {notice ? <StatusMessage tone="neutral" message={notice} /> : null}
      {error ? <StatusMessage tone="error" message={error} /> : null}
    </form>
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
  const selectedGroups = groupTechniquesByTactic(techniqueIds, lookup);

  return (
    <div className="selected-techniques">
      <div className="mini-header">
        <strong>{techniqueIds.length} known selected</strong>
        {unknownIds.length > 0 ? <span className="error-text">{unknownIds.length} unknown</span> : null}
      </div>
      <div className="selected-technique-groups">
        {selectedGroups.map((group) => (
          <div className="selected-technique-group" key={group.tactic}>
            <strong>{formatTactic(group.tactic)}</strong>
            <div className="chip-list">
              {group.techniques.map((technique) => (
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
            </div>
          </div>
        ))}
        {selectedTechniques.length === 0 && unknownIds.length === 0 ? <p className="muted">No techniques selected.</p> : null}
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
  deleting,
  groups,
  techniqueIds,
  techniqueLookup,
  onEdit,
  onDelete
}: {
  profile: ComparableProfile | null;
  customProfile: TTPProfile | null;
  actorDetail: ActorDetail | null;
  detailLoading: boolean;
  deleting: boolean;
  groups: ReturnType<typeof groupTechniquesByTactic>;
  techniqueIds: string[];
  techniqueLookup: TechniqueLookup;
  onEdit: (profile: TTPProfile) => void;
  onDelete: (profile: TTPProfile) => void;
}) {
  if (!profile) {
    return (
      <section className="results-panel profile-results">
        <div className="empty-state">
          <FileJson size={24} aria-hidden="true" />
          <p>Select a profile to inspect its techniques and metadata.</p>
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
          {customProfile ? (
            <>
              <button type="button" title="Edit Custom TTP Profile" onClick={() => onEdit(customProfile)}>
                <Edit size={16} aria-hidden="true" />
              </button>
              <button type="button" title="Delete Custom TTP Profile" disabled={deleting} onClick={() => onDelete(customProfile)}>
                {deleting ? <Loader2 className="spin" size={16} aria-hidden="true" /> : <Trash2 size={16} aria-hidden="true" />}
              </button>
            </>
          ) : null}
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

        {actorDetail?.description ? (
          <div className="why-match">
            <strong>Description</strong>
            <p style={{ whiteSpace: "pre-wrap", lineHeight: 1.55, fontSize: "0.82rem" }}>
              {actorDetail.description}
            </p>
          </div>
        ) : null}

        {actorDetail ? <SoftwareList software={actorDetail.software_used} /> : null}
        {actorDetail ? (
          <EnrichmentTags
            sectors={actorDetail.target_sectors}
            countries={actorDetail.target_countries}
            cves={actorDetail.cves_exploited}
            motivation={actorDetail.motivation}
          />
        ) : null}
        {customProfile && (
          (customProfile.target_sectors?.length > 0 ||
           customProfile.target_countries?.length > 0 ||
           customProfile.cves_exploited?.length > 0 ||
           customProfile.motivation)
        ) ? (
          <EnrichmentTags
            sectors={customProfile.target_sectors ?? []}
            countries={customProfile.target_countries ?? []}
            cves={customProfile.cves_exploited ?? []}
            motivation={customProfile.motivation ?? null}
          />
        ) : null}

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

function EnrichmentTags({
  sectors,
  countries,
  cves,
  motivation,
}: {
  sectors: string[];
  countries: string[];
  cves: string[];
  motivation: string | null;
}) {
  const hasData = sectors.length > 0 || countries.length > 0 || cves.length > 0 || motivation;
  if (!hasData) return null;

  return (
    <div className="why-match" style={{ display: "grid", gap: 8 }}>
      {motivation ? (
        <div>
          <strong style={{ fontSize: "0.8rem", textTransform: "uppercase", color: "#52606a" }}>Motivation</strong>
          <div className="chip-list" style={{ marginTop: 4 }}>
            <span className="technique-chip">{motivation}</span>
          </div>
        </div>
      ) : null}
      {sectors.length > 0 ? (
        <div>
          <strong style={{ fontSize: "0.8rem", textTransform: "uppercase", color: "#52606a" }}>Target sectors</strong>
          <div className="chip-list" style={{ marginTop: 4 }}>
            {sectors.slice(0, 12).map((s) => (
              <span className="technique-chip" key={s}>{s}</span>
            ))}
            {sectors.length > 12 ? <span className="technique-chip unknown-chip">+{sectors.length - 12} more</span> : null}
          </div>
        </div>
      ) : null}
      {countries.length > 0 ? (
        <div>
          <strong style={{ fontSize: "0.8rem", textTransform: "uppercase", color: "#52606a" }}>Target countries</strong>
          <div className="chip-list" style={{ marginTop: 4 }}>
            {countries.slice(0, 12).map((c) => (
              <span className="technique-chip" key={c}>{c}</span>
            ))}
            {countries.length > 12 ? <span className="technique-chip unknown-chip">+{countries.length - 12} more</span> : null}
          </div>
        </div>
      ) : null}
      {cves.length > 0 ? (
        <div>
          <strong style={{ fontSize: "0.8rem", textTransform: "uppercase", color: "#52606a" }}>CVEs exploited</strong>
          <div className="chip-list" style={{ marginTop: 4 }}>
            {cves.slice(0, 10).map((cve) => (
              <span className="technique-chip unknown-chip" key={cve} style={{ fontFamily: "monospace", fontSize: "0.78rem" }}>{cve}</span>
            ))}
            {cves.length > 10 ? <span className="technique-chip unknown-chip">+{cves.length - 10} more</span> : null}
          </div>
        </div>
      ) : null}
    </div>
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
    sorting: 0,
    layout: { layout: "side", aggregateFunction: "average", showID: true, showName: true },
    hideDisabled: false,
    gradient: {
      colors: ["#ffd9b3", "#ff6b00"],
      minValue: 0,
      maxValue: 100
    },
    legendItems: [
      { label: name, color: "#ff8a4c" }
    ],
    techniques: techniqueIds.map((techniqueID) => ({
      techniqueID,
      color: "#ff8a4c",
      enabled: true,
      comment: `Included in profile: ${name}`
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
