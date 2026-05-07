# DEV STATE

## Last updated: 2026-05-07

### Completed this session

**Session 25 — Graph canvas drag + PNG export + graph readability**
- `ActorNetworkGraphPanel`: canvas drag-to-pan — `canvasDragRef` tracks background pointer events; node `onPointerDown` still uses `stopPropagation` so node drag and canvas drag don't conflict; cursor changes to `grabbing` during drag
- PNG export: `exportAsImage()` serializes SVG clone with inline styles + dark background rect, renders to 2× canvas via `Image` + `canvas.toBlob()`, downloads as `whoiswhoapt-network.png`; `📷` Camera button in graph controls; JSON export button removed
- Graph readability: `.network-node-label` with `paint-order: stroke` halo (white outline behind text), `.network-edge` with `rgba(255,255,255,0.35)` + opacity proportional to similarity, edge % labels at midpoint with semi-transparent backdrop, `.comparison-graph-edge` also brighter
- `ActorNetworkGraphPanel`: "Fit" button calculates bounding box and auto-adjusts zoom+pan; zoom minimum lowered from 0.6 → 0.15

**Session 24 — Graph visibility: node labels, edges, % labels**
- Network graph: node labels `paint-order: stroke` halo for readability; edges `rgba(255,255,255,0.35)` with similarity-proportional opacity; edge % labels (badge rect + monospace text) for similarities ≥10%; node glow ring + full color fill
- Comparison graph: stronger edge color, improved label stroke for readability

**Session 23 — 8 improvements (commit 0e83d15)**
- DEV_STATE documented sessions 17-22
- TTP Profiles inspector: full actor description shown in body panel
- Explore network graph: full D3 pointer-based node drag (simulationRef persists simulation; node fixed on drag, alpha releases on drop)
- OpenCTI ICS supplement: `ingestion.py` supplements MitreSource Enterprise techniques with T0xxx ICS techniques from OpenCTI adapter
- Frontend tests: `exportUtils.test.ts` (13 tests for CSV/Navigator/JSON); `ttpProfileUtils.test.ts` extended with `splitTactics()` and `techniqueName()` including bad-data guard and sub-technique parent prefix
- Saved analyses re-run: "Re-run" button calls compareActor/compareTTPProfile with original params; fresh result shown in ComparisonResultTabs; canSave=true on fresh result
- Navigator export: `tacticFor()` adds first individual tactic to each technique entry

**Session 22 — Export fixes + saved analyses visibility**
- CSV export: info header block + columns (rank, actor_name, similarity_pct, shared_ttp_count, input/target only counts, IDs, names, software); scores as `%` strings
- Navigator comparison: `gradient` field so scores map to visible colors; source-only techniques in blue `#4a9eff`; legend items; sorting/layout fields
- Navigator individual profile (TTP Profiles): techniques colored orange `#ff8a4c` with comment and layout
- Saved analyses list: explicit `color: var(--text-1)` on buttons (was near-invisible); `background: var(--bg-3)` + border; 3-line layout (name / meta / date)

**Session 21 — Explore all-vs-all + heatmap fixes + Settings dark theme + metric options**
- `ActorSimilarityPanel`: extracts all unique actor pairs from matrix, ranks by score, slider threshold (0-80%), paginated 50-at-a-time; true all-vs-all — no actor selection needed
- Heatmap: removed "Search in matrix" filter; legend now shows real gradient bar (black→teal→orange) with 0/25/50/75/100% ticks; single-actor filter result shows friendly message
- All metric selectors (Heatmap, Graph, SimilarityPanel, ActorComparisonPanel): include Holistic option
- Settings stat cards: replaced hardcoded light backgrounds (`#f7f9fa`) with CSS variables (`--bg-3`, `--accent-text`, `--text-3`); environment badge uses `.metric-label` class

**Session 20 — Tactic breakdown correctness + NULL coercion fix**
- `similarity.py`: `_primary_tactic_for()` for grouping (first individual tactic); shared counts now sum to pill total; all ~15 tactics shown (no more 6-row limit)
- `schemas.py`: `@field_validator` coerces NULL DB values to `[]` for CustomTTPSet list fields

**Session 19 — Custom TTP profiles enrichment + holistic scoring for custom profiles**
- `CustomTTPSet`: `target_sectors`, `target_countries`, `cves_exploited`, `motivation` columns + auto-migration
- `compare.py`: holistic for custom profiles uses their enrichment as source input
- Frontend: `TTPProfilePayload`; 4 new form inputs; inspector shows `EnrichmentTags`; `openEditForm` pre-fills

**Session 18 — Holistic similarity metric**
- `"holistic"` metric: techniques 60% + sectors 15% + countries 10% + CVEs 10% + motivation 5%; adaptive weight renormalization when dimensions absent
- `EntityTechniqueSet` extended with enrichment frozenset fields
- Actor-vs-all and custom comparison paths both support holistic

**Session 17 — Frontend dark theme, compare UX, explore improvements**
- Complete `styles.css` dark theme (CSS variables, Inter + JetBrains Mono)
- Sidebar: panda logo, WORKSPACE/RECENT sections, badge counts, health-card footer
- Compare: dynamic title, SourceProfileCard, stepper TopN, segmented scope buttons, results summary bar, ActorProfilePanel expandable, technique breakdown, SharedContextRow, ActorContextPanel
- Graph/Heatmap: colored nodes + edge % labels, real color scale, cell size adapts to actor count
- TTP Profiles: layout fix, technique picker dark styling

**Session 16 — Tactic breakdown correctness**
- `similarity.py`: `_primary_tactic_for()` splits comma-separated tactic strings and returns the first individual tactic; `tactic_breakdown()` now uses it so each technique belongs to exactly one bucket and shared counts sum to the pill total; `_tactic_for()` unchanged (still used for scoring)
- `ComparisonRankingView`: removed `.slice(0, 6)` limit — all ~12-15 tactics now shown
- `schemas.py`: `@field_validator` coerces NULL DB values to `[]` for CustomTTPSet list fields (fixes 500 on pre-migration rows)

**Session 15 — Custom TTP profiles enrichment + holistic scoring for custom profiles**
- `CustomTTPSet` entity + schema: `target_sectors`, `target_countries`, `cves_exploited`, `motivation`
- Auto-migration in `database.py` for 4 new columns
- `custom_sets.py`: create/update persist enrichment via `_normalize_tags()`
- `compare.py`: holistic metric for custom profiles uses their enrichment as source input
- Frontend: `TTPProfilePayload` interface; form with 4 new inputs (comma-separated); inspector shows `EnrichmentTags` for custom profiles; `openEditForm` pre-fills

**Session 14 — Holistic similarity metric**
- `comparison.py`: `"holistic"` added to `SimilarityMetric`; `EntityTechniqueSet` extended with `sectors/countries/cves/motivation` (frozenset fields); `_holistic_score()` with adaptive weight renormalization; `compare_pair()` dispatches to holistic; `compare_against_entities()` accepts holistic enrichment params
- `schemas.py`: `"holistic"` added to SimilarityMetric Literal
- `compare.py`: `_actor_candidates_holistic()`, `_source_enrichment()` — actor-vs-all and custom paths both support holistic
- Default weights: techniques 60%, sectors 15%, countries 10%, CVEs 10%, motivation 5%
- Frontend: "Holistic" option in dropdown with contextual hint; validated live

**Session 13 — Settings panel overhaul + settings API tests**
- Settings panel: radio fieldset source selector, SourceStatusPanel with 4-metric grid (actors/campaigns/software/techniques), test connection → green success, save → flash message, load button hidden when no config, scheduler rewires on save
- 11 new API tests for GET/PUT /api/settings, GET /api/source/status, POST /api/source/test-connection

**Session 12 — Frontend dark theme from Claude Design + compare UX iteration**
- Complete `styles.css` rewrite: dark theme CSS variables (`--bg-0` → `--bg-5`, `--accent: #ff8a4c`), Inter + JetBrains Mono fonts
- `Sidebar`: panda-octopus logo, WORKSPACE label, RECENT section with last 2 analyses, badge counts, health-card footer
- Compare: dynamic title "Who looks like {actor}?", `SourceProfileCard`, stepper for TopN, segmented scope buttons, `► Run comparison`
- `ComparisonResultTabs`: compact results summary bar, `ActorProfilePanel` (expandable with description/stats/techniques), icon-only Re-run/Save buttons
- `ComparisonRankingView`: `ScoreBadge` with % + SIMILARITY + spark bar, rank `01/RANK`, meta-pills (shared/input-only/target-only), `TacticBreakdownList` 2-column grid, `TechniqueBreakdownPanel` collapsible (kept), `ActorContextPanel` collapsible with description
- Graph nodes: colored palette, white text, edge % labels
- Heatmap: dark color scale (black→teal→orange), dynamic cell sizes, rotated column headers
- TTP Profiles: layout fix, technique picker dark styling, textarea/file input dark

**Session 11 — Compare UX: dynamic labels, technique breakdown, tactic filter fix, MITRE technique names**
- `ingestion.py`: always loads techniques from `MitreSource` (fixes bad names from OpenCTI instances)
- `ttpProfileUtils`: `techniqueName()` for sub-technique full names, `splitTactics()` for filter
- `ActorComparisonPanel`: tactic dropdown splits compound strings, no more "execution, persistence" options
- `ComparisonRankingView`: removed noisy inline technique preview, technique breakdown colapsable (3 columns), `ActorContextPanel` with actor description, `SharedContextRow` for shared sectors/countries, meta-pills with "TTPs" suffix
- `database.py`: `_apply_column_migrations()` idempotent ALTER TABLE

**Session 10 — fastapi 0.129.2 + pycti 7.x upgrade**
- Updated `requirements.txt`: `fastapi>=0.129.2,<0.130.0` (unpinned minor), `uvicorn[standard]>=0.34.2`, `pycti==7.260430.0`
- Zero code changes required — all 114 tests pass without modification
- pycti 7.x connects to OpenCTI 7.260423.0 via the same GraphQL API; field names unchanged
- Data improvement vs pycti 6.x: 240 actors (+7), 1292 software (+15), 968 techniques, 60 campaigns
- Build validated end-to-end: health ✓, OpenCTI test-connection ✓, source load ✓

**Session 9 — Enrichment filter in Explore (Heatmap + Graph)**
- Backend: `ActorEnrichmentIndexItem` schema + `GET /api/source/actor-enrichment-index` — returns `{id, target_sectors, target_countries}` for all actors in active source that have enrichment data
- Extracted `EnrichmentFilterPanel` from `ActorComparisonPanel.tsx` to `EnrichmentFilterPanel.tsx` — shared component, accepts optional `hint` prop
- `graphUtils.ts` `buildGraphData()`: new optional `allowedActorIds: Set<string> | null` param — filters `actorScores` before slicing to `nodeLimit`
- `ActorMatrixHeatmapPanel`: enrichment options + index fetched on mount; `allowedActorIds` derived via `useMemo`; filter applied in `useVisibleActorIndexes`; `EnrichmentFilterPanel` shown when data available
- `ActorNetworkGraphPanel`: same pattern; `allowedActorIds` passed through `NetworkPanel` → `useGraphData` → `buildGraphData`
- Both panels: filter is client-side on already-computed matrix data — no matrix recomputation needed
- All validated end-to-end: 36 actors with enrichment data indexed, filter applied client-side on matrix, no matrix recomputation needed

**Session 8 — Persist enrichment filters in saved analyses**
- Added `filter_sectors` and `filter_countries` JSON nullable columns to `Analysis` entity
- Added fields to `AnalysisCreateRequest` and `AnalysisResponse` schemas
- `save_analysis` route persists both fields; `_analysis_response` returns them
- Frontend: `AnalysisCreateRequest` and `AnalysisResponse` types updated; `ComparisonResultTabs` and `ComparisonResults` components accept `filterSectors`/`filterCountries` and pass them to `saveAnalysis`
- `SavedAnalysisViewModel` extended with `enrichmentFilterLabel`, `filterSectors`, `filterCountries`
- `savedAnalysisEnrichmentFilterLabel()` helper added to `savedAnalysisUtils.ts`
- Saved analysis inspector shows enrichment filter in green when present ("Filter: Sectors: ... · Countries: ...")
- `_apply_column_migrations()` added to `init_db()` — idempotent `ALTER TABLE` for `analyses.filter_sectors/countries` and `campaigns.target_sectors/countries`; safe to run on both fresh and existing DBs
- Validated live: `filter_sectors: ["Energy"]` persists and is returned in saved analysis detail; 114/114 tests passing

**Session 7 — Enrichment filter in Compare**
- Added `filter_sectors` and `filter_countries` optional fields to `ActorComparisonRequest`, `CustomComparisonRequest`, `IncidentAnalysisRequest`
- Added `_filter_candidates_by_enrichment()` in compare route — pre-filters actor candidates by sector/country (OR within each list, AND between lists) before scoring; no-op when no filter
- Added `EnrichmentOptions` schema and `GET /api/source/enrichment-options` endpoint — returns sorted distinct sectors/countries from active source actors
- Frontend: `getEnrichmentOptions()` client function; `EnrichmentFilterPanel` component in `ActorComparisonPanel` — two multi-select boxes (sectors/countries), only shown for OpenCTI source, clear button when active filter
- Validated live: MuddyWater + Energy filter → 3 actors from 233 (APT28, Hydra Saiga, CL-UNK-1068), all confirmed with Energy in their sectors
- Full test suite: 114/114 passing

**Session 6 — Enrichment in Compare results**
- Added `ActorEnrichment` schema (`target_sectors`, `target_countries`, `cves_exploited`, `motivation`)
- Added `enrichment: ActorEnrichment | None` field to `ComparisonResult` schema
- Added `_enrichment_lookup(session, actor_ids)` — single batch query for all matched actors in a comparison
- Wired enrichment into all three compare code paths (actor-vs-actor, actor-vs-all, custom/incident)
- Frontend: `ActorEnrichment` type added; `EnrichmentRow` component in `ComparisonRankingView` — shows motivation, sectors, countries, CVEs chips per result row
- CSS: `.result-enrichment` / `.enrichment-item` / `.enrichment-label` styles
- Validated live: MuddyWater comparison → MUSTANG PANDA 3 sectors · 13 countries, Kimsuky 2 sectors
- Full test suite: 114/114 passing

**Session 5 — Enrichment fields + scheduler wiring**
- Extracted scheduler logic to `app/scheduler.py` (avoids circular import between `main.py` and settings route)
- `PUT /api/settings` now calls `scheduler.reschedule(hours)` — interval changes take effect immediately without restart
- Added `target_sectors`, `target_countries`, `cves_exploited`, `motivation` to `ActorDetail` API schema and route
- Added `target_sectors`, `target_countries` columns to `Campaign` entity + schema
- Updated `fetch_campaigns()` in `OpenCTIAdapter` to populate sectors/countries/CVEs from `targets` relationships
- Frontend: `ActorDetail` type updated with new fields; `EnrichmentTags` component added to `ProfileInspector` — shows motivation, target sectors, target countries, CVEs as chips
- Validated live: MuddyWater → 9 sectors, 11 countries, 13 CVEs from OpenCTI
- Full test suite: 114/114 passing

**Session 4 — End-to-end hardening + live OpenCTI validation**
- Pinned `pycti==6.8.14` in `requirements.txt` (pycti 7.x requires fastapi>=0.129 which is incompatible; 6.x works with OpenCTI 7.x server via GraphQL)
- Added `libmagic1` to Dockerfile (required by python-magic, a pycti dependency)
- Added `apscheduler==3.10.4` to `requirements.txt`
- Added `backend/requirements-dev.txt` with pytest + httpx for local test runs
- Fixed `test_connection()`: replaced non-existent `get_opencti_version()` with `health_check()`
- Fixed `get_source_version()`: uses `client.query("{about{version}}")["data"]["about"]["version"]`
- Fixed `_tactic_from_item()`: kill_chain_name filter changed to `startswith("mitre-attack")` to handle `mitre-attack-v19` versioned chains from pycti 6.x (dedup handles the duplicate)
- Fixed `_build_ap_mitre_map()`: `(item.get("x_mitre_id") or "").startswith("T")` to safely handle None values
- Added `_targets_rels()` helper — fetches all `targets` relationships from Intrusion-Set to any entity
- Updated `fetch_actors()` to populate `target_sectors`, `target_countries`, `cves_exploited` from `targets` relationships (entity_type-dispatched: Sector/Country/Vulnerability)
- Replaced deprecated `@app.on_event("startup")` with FastAPI `lifespan` context manager
- Added APScheduler `BackgroundScheduler` — starts on app startup, reschedules based on active source's `update_frequency_hours`, reads settings on each tick to respect `auto_update` flag
- Updated tests: `test_connection` and `get_source_version` mocks updated to match new API (`health_check`, `query`); added test for versioned chain dedup
- Full test suite: 114/114 passing
- **Live validation**: loaded 233 actors, 60 campaigns, 1277 software, 967 techniques from OpenCTI 7.260423.0

**Session 1 — Adapter + Settings UI**
- Added `test_connection()` non-abstract method to `BaseSource`
- Created `OpenCTIAdapter(BaseSource)` in `backend/app/sources/opencti.py` using `pycti`
  - Implements `fetch_techniques`, `fetch_actors`, `fetch_campaigns`, `fetch_software`, `get_source_version`, `test_connection`
  - Resolves actor/campaign/software ↔ technique relationships via pycti stix_core_relationship queries
- Updated `get_source_adapter()` factory in `ingestion.py` to support `"opencti"` (lazy pycti import)
- Added `ConnectionTestRequest` and `ConnectionTestResult` to `schemas.py`
- Added `POST /api/source/test-connection` endpoint
- Added `pycti>=6.0.0` to `requirements.txt`
- Added settings types + client functions to frontend
- Rewrote `SettingsPanel.tsx` — source selector, OpenCTI config form, test-connection flow, save, status panel

**Session 3 — Multi-source stabilization**
- Fixed `_tactic_from_item()` in `opencti.py`: now lowercase, sorted, deduplicated, `", "` separator — matches MitreSource format exactly
- Fixed defensive lowercase in `mitre.py` `fetch_techniques()`: `{t.strip().lower() for t in tactics}` (no behavioural change, just guards against upstream mixed case)
- Added `backend/tests/test_opencti_source.py` — 23 tests covering helpers (`_tactic_from_item`, `_internal_id`, `_aliases`, `_build_ap_mitre_map`, `_build_technique_refs`) and adapter methods (`fetch_techniques`, `test_connection`, `get_source_version`) using `sys.modules` pycti mock
- Added `backend/tests/test_multi_source_ingestion.py` — 18 tests covering factory behavior, DB source isolation (MITRE rows survive OpenCTI ingestion and vice-versa), CustomTTPSet survival, technique table replacement, and `_technique_has_tactic()` regression across both tactic formats
- Full test suite: 112/112 passing

**Session 2 — Report ingestion + source awareness**
- Added `search_reports()` and `fetch_report_technique_ids()` to `OpenCTIAdapter`
  - Two-strategy technique extraction: embedded objects → fallback containedBy filter
- Added `OpenCTIReport` and `ReportTechniquesResponse` schemas
- Added `GET /api/source/reports?q=` and `GET /api/source/reports/{id}/techniques` endpoints
- Added `searchReports()` and `getReportTechniques()` to frontend client
- Wired `activeSource` through `App.tsx` → `ActorComparisonPanel` and `TTPProfilesPanel`
  - Footer `BackendStrip` now shows active source name
  - Compare source pill shows "MITRE ATT&CK · N profiles" or "OpenCTI · N profiles"
- Created `OpenCTIReportImporter.tsx` — collapsible import panel with search → report list → technique preview → import
- Integrated report importer into TTPProfilesPanel library sidebar (visible only when OpenCTI is active)
  - Import pre-fills the profile create form with report name + valid technique IDs
  - Skipped techniques (not in current dataset) shown as a notice

### Current module status
- Compare: `activeSource` prop wired, source name shown in pill
- TTP Profiles: `activeSource` prop wired, OpenCTI report importer in sidebar when source is OpenCTI
- Explore (Visual Analysis): unchanged
- Settings: source selector + OpenCTI config form + ingestion status panel

### Decisions made
- `test_connection()` on `BaseSource` is non-abstract no-op; only `OpenCTIAdapter` overrides it
- `test-connection` endpoint accepts URL + token in request body — test before saving credentials
- Save button in Settings requires a successful connection test in the current session (OpenCTI only)
- Load data button enabled when saved credentials are present in persisted settings
- Lazy import of `OpenCTIAdapter` in `get_source_adapter()` — app starts normally if pycti is missing and MITRE is active
- OpenCTI `fetch_techniques()` requires MITRE ATT&CK dataset imported in the OpenCTI instance (standard for most deployments)
- `target_sectors`, `target_countries`, `cves_exploited` on actors now populated via `targets` relationships — stored in DB but not yet surfaced in `ActorDetail` API response
- Report importer uses two-strategy technique extraction: primary (embedded objects in report.read()) → fallback (containedBy filter on attack_pattern.list())
- `activeSource` is fetched once on App mount from `GET /api/settings` and passed down as a prop — no global context needed at this scale

### Next steps
- Comparison graph (Compare tab) `📷` image export — same as Explore network graph
- TTP Profiles: Navigator export could include `tactic` field (already done for comparison Navigator; profile export uses color only)
- Explore heatmap: show % in cells when > 25 actors (currently hidden for cell size)
- Saved analyses: persist metric hint / enrichment filter info in the list view
- Settings: OpenCTI auto-refresh status indicator (shows when next scheduled reload is)
- Frontend React component tests (no DOM tests exist, only utility tests)

---

## Current Status

Project: WhoIsWhoAPT v2
Stage: Iteration 5 complete — Multi-dimensional scoring, enriched custom profiles, dark theme, tactic breakdown correctness

The system is now a functional CTI analysis tool with:

* Actor and TTP profile comparison
* Custom TTP profile creation/editing
* Tactic-scoped similarity
* Multiple similarity metrics
* Visualizations (ranking, heatmap, graph)
* Analysis persistence (save, list, inspect, delete)

---

## Current Architecture

### Backend

* FastAPI
* SQLite
* Modular analytics engine
* Entities:

  * Actor (MITRE)
  * Custom TTP Profile
  * Analysis (new)

### Frontend

* React + Vite
* Modular layout:

  * Compare
  * TTP Profiles
  * Explore
  * Settings

---

## Product Model

Key abstraction:

> A "TTP Profile" represents any entity defined by techniques.

Types:

* Actor profile (MITRE/OpenCTI future)
* Custom TTP profile

Comparison model:

```text
Source Profile → Compare → Target Profiles → Results
```

---

## Completed Iterations

### Iteration 3.5

* Modular UI
* Unified Compare views
* TTP Profiles consolidation

### Iteration 3.6

* Cleanup and naming consistency
* TTP Profiles as a library
* Unified profile selectors in Compare
* Custom profile CRUD (create/edit/delete)

### Iteration 3.7

* Analysis persistence
* Saved Analyses UI
* Hardening (UX + backend validation)

---

## Current Capabilities

* Compare actor vs actors
* Compare custom profile vs actors
* Tactic filtering
* Multiple scoring models
* Explainability (shared, unique, tactic breakdown)
* Save analysis results
* Inspect saved analyses
* Delete saved analyses

---

## Known Limitations

* No OpenCTI integration yet
* Single data source (MITRE only)
* No enrichment
* No re-run of saved analyses
* No multi-user support
* No authentication

---

## Next Step (IMPORTANT)

Next iteration:

### Iteration 4 — OpenCTI MVP (read-only integration)

Goal:

* Use OpenCTI as a data source instead of only MITRE
* Ingest:

  * Actors
  * Campaigns (optional)
  * Software
* Map OpenCTI entities to TTP Profiles

Constraints:

* Read-only integration
* No sync complexity
* No background jobs
* Do not break current MITRE flow

---

## Development Rules

* Do NOT break existing comparison flows
* Do NOT change scoring logic unless necessary
* Reuse existing abstractions (TTP Profile)
* Keep UI modular
* Prefer minimal backend changes
* Maintain backward compatibility

---

## Testing

Backend:

* Run: python -m pytest (from backend directory)

Frontend:

* docker compose run --rm frontend npm run test
* docker compose run --rm frontend npm run build
* docker compose run --rm frontend npm run lint

---

## Notes

The project is transitioning from a prototype into a structured CTI tool.

Focus is now on:

* Data integration (OpenCTI)
* Real-world workflows
* Stability over feature expansion
