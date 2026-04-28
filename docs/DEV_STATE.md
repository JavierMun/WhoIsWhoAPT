# DEV STATE

## Last updated: 2026-04-28

### Completed this session

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
- `target_sectors` and `target_countries` on actors left empty — require additional relationship queries; deferred to a later iteration
- Report importer uses two-strategy technique extraction: primary (embedded objects in report.read()) → fallback (containedBy filter on attack_pattern.list())
- `activeSource` is fetched once on App mount from `GET /api/settings` and passed down as a prop — no global context needed at this scale

### Next steps
- Rebuild Docker image to install `pycti>=6.0.0` and test end-to-end with a real OpenCTI instance
- Verify pycti field names (`killChainPhases`, relationship query kwargs, `search` param on report.list) against installed pycti version
- Add auto-update scheduler for OpenCTI (APScheduler) — Iteration 4 deferred item
- Add `target_sectors` and `target_countries` ingestion via OpenCTI location/sector relationships
- Consider adding CVE linkage via OpenCTI vulnerability relationships

---

## Current Status

Project: WhoIsWhoAPT v2
Stage: Iteration 4 (OpenCTI integration — backend adapter + settings UI complete)

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
