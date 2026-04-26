# Iteration 3.6 Part 2 - Profile Library and Unified Compare

## Implemented

The frontend now treats a profile as any comparable TTP-based entity:

- Actor Profile from the active data source
- Custom TTP Profile created by the user
- Imported Navigator profile saved as a Custom TTP Profile

The module order remains:

1. Compare
2. TTP Profiles
3. Explore
4. Settings

## TTP Profiles

`TTP Profiles` is now a TTP profile library and management workspace.

It supports:

- browsing Actor Profiles from the active source
- browsing Custom TTP Profiles
- creating a new Custom TTP Profile
- pasting technique IDs
- importing Navigator JSON
- searching, filtering, and selecting techniques
- saving custom profiles
- inspecting profile details

The inspector shows:

- name
- type: Actor Profile or Custom TTP Profile
- description when available
- number of techniques
- techniques grouped by tactic
- technique ID and technique name
- software for Actor Profiles when available

The module no longer runs comparisons directly. Comparison analysis now lives in `Compare`.

## Compare

`Compare` is now the analysis workspace with unified profile selectors.

It includes:

- one `Source profile` selector
- grouped source options with Custom TTP Profiles first, Actor Profiles second
- target scope:
  - compare against all actor profiles
  - compare against selected profiles
- one unified `Target profiles` picker when selected targets are enabled
- grouped target options with Custom TTP Profiles first, Actor Profiles second
- existing metric, tactic scope, and result-count controls
- existing Ranking, Heatmap, and Graph result tabs
- existing comparison exports

Custom profile targets are shown for UX consistency, but custom-vs-custom scoring is still future support. Current selected-target comparison runs against selected Actor Profile targets.

## Backend

Backend behavior is unchanged for existing callers and endpoint paths remain intact.

One backward-compatible field was added to `POST /api/compare/custom`:

```json
{
  "target_ids": ["actor-id"]
}
```

When present, it reuses the existing actor target filtering helper before calling the same comparison engine. No scoring logic or algorithms were duplicated.

## Frontend Representation

The frontend uses `ComparableProfile` in `frontend/src/api/profileLibraryUtils.ts`:

```ts
type ComparableProfile = {
  id: string;
  key: string;
  name: string;
  type: "actor" | "custom";
  description?: string | null;
  technique_ids?: string[];
  technique_count: number;
};
```

Actors and Custom TTP Profiles are normalized only in the frontend for selector and library workflows.

## Comparison Routing

- Actor source + all actor profiles: `POST /api/compare/actor`
- Actor source + selected Actor Profile targets: `POST /api/compare/actor` with `target_ids`
- Custom TTP Profile source + all actor profiles: `POST /api/compare/custom`
- Custom TTP Profile source + selected Actor Profile targets: `POST /api/compare/custom` with `target_ids`
- Custom TTP Profile targets in the target picker: visible with a clear future-support notice

Tactic-scoped filtering is passed through both actor and custom comparison routes.

## Files Changed

- `backend/app/models/schemas.py`
- `backend/app/api/routes/compare.py`
- `backend/tests/test_compare_api.py`
- `frontend/src/api/client.ts`
- `frontend/src/api/types.ts`
- `frontend/src/api/profileLibraryUtils.ts`
- `frontend/src/api/profileLibraryUtils.test.ts`
- `frontend/src/components/ActorComparisonPanel.tsx`
- `frontend/src/components/TTPProfilesPanel.tsx`
- `frontend/src/components/ComparisonResultTabs.tsx`
- `frontend/src/styles.css`

## Manual Test

1. Open `Compare`.
2. Confirm source options show Custom TTP Profiles first and Actor Profiles second.
3. Compare an Actor Profile source against all actor profiles.
4. Compare an Actor Profile source against selected Actor Profile targets.
5. Compare a Custom TTP Profile source against all actor profiles.
6. Compare a Custom TTP Profile source against selected Actor Profile targets.
7. Select a Custom TTP Profile target and confirm the future-support notice is shown.
8. Confirm Ranking, Heatmap, and Graph tabs still render.
9. Open `TTP Profiles`.
10. Confirm Actor Profiles and Custom TTP Profiles are browsable.
11. Inspect an Actor Profile and confirm grouped techniques and software render when available.
12. Create/import/save a Custom TTP Profile and inspect it in the library.

## Validation

Backend:

```powershell
cd backend
python -m pytest
```

Frontend:

```powershell
docker compose run --rm frontend npm run test
docker compose run --rm frontend npm run build
docker compose run --rm frontend npm run lint
```
