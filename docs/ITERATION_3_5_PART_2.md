# Iteration 3.5 Part 2 - Unified TTP Profiles Workflow

## Implemented

The TTP Profiles module now uses one consolidated workflow instead of separate Custom TTP Sets and Incident Analysis panels.

The product concept is now a reusable TTP Profile:

- a manually created technique collection
- a Navigator-imported technique collection
- an incident-derived observed TTP collection

Saved profiles continue to use the existing custom set storage and comparison endpoints.

## Backend

No backend schema change was required.

The existing `custom_ttp_sets` table already stores:

- `name`
- `description`
- `technique_ids`
- timestamps

The existing endpoints remain in place:

- `POST /api/custom-sets`
- `GET /api/custom-sets`
- `GET /api/custom-sets/{id}`
- `POST /api/compare/custom`
- `POST /api/analyze/incident`

`POST /api/analyze/incident` still works for backward compatibility, but the frontend now saves and compares incident-like inputs as TTP profiles through the custom-set flow.

## Frontend

The TTP Profiles module now renders:

- `TTPProfilesPanel`

It replaces the previous split rendering of:

- `CustomTTPSetPanel`
- `IncidentAnalysisPanel`

The unified panel supports:

- profile name
- optional description
- fast paste of ATT&CK technique IDs
- ATT&CK Navigator JSON import
- technique search and selection
- tactic filtering
- save profile
- clear form
- saved profile selection
- saved profile inspection
- profile comparison against actors
- profile Navigator export
- comparison JSON, CSV, and Navigator exports

## Saved Profile Inspection

When a saved profile is selected, the UI shows:

- profile name
- description
- number of techniques
- last updated timestamp
- techniques grouped by tactic
- each technique ID and technique name

Technique metadata comes from the existing `GET /api/techniques` response and is matched locally against each saved profile's `technique_ids`.

## Validation

Technique IDs are normalized in the frontend before save or comparison:

- trim whitespace
- uppercase IDs
- deduplicate
- sort for stable display

Unknown technique IDs are shown before saving, and the backend validation remains the final source of truth.

## Manual Test

Start the stack:

```powershell
docker compose up -d --build backend frontend
```

Open:

```text
http://localhost:5173
```

Test TTP Profiles:

1. Open the TTP Profiles module.
2. Enter a profile name and optional description.
3. Paste IDs such as `t1059, T1105`.
4. Search for another technique and add it.
5. Filter the technique list by tactic.
6. Save the profile.
7. Select the saved profile.
8. Confirm techniques are grouped by tactic with IDs and names.
9. Compare the profile.
10. Export comparison JSON, CSV, and Navigator layer.
11. Export the saved profile as a Navigator layer.
12. Use Clear form and confirm saved profile inspection remains intact.

Regression checks:

- Actor Comparison still renders and compares actors.
- Visual Analysis still renders heatmap and graph panels.
- Existing backend custom comparison and incident analysis endpoints remain available.

## Validation Commands

Frontend:

```powershell
docker compose run --rm frontend npm run test
docker compose run --rm frontend npm run build
docker compose run --rm frontend npm run lint
```

Backend tests are not required for this part because no backend code or schema was changed.
