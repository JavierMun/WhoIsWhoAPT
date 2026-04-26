# Iteration 3.6 Part 1 - Cleanup and UX Polish

## Removed

- Removed the legacy `CustomTTPSetPanel` frontend component.
- Removed the legacy `IncidentAnalysisPanel` frontend component.
- Removed the unused frontend incident-analysis API helper.
- Pruned CSS selectors that only supported the removed legacy panels.

`TTPProfilesPanel` is now the only frontend entry point for TTP profile workflows, and `ActorComparisonPanel` remains the only comparison UI.

## Renamed

- Sidebar label `Visual Analysis` is now `Explore`.
- Frontend-facing custom-set client names now use TTP Profile terminology:
  - `getTTPProfiles`
  - `createTTPProfile`
  - `compareTTPProfile`
  - `TTPProfile`

Backend endpoint paths and payload fields were left intact for compatibility.

## Cleaned

- Improved empty-state copy:
  - `No matching actors found`
  - `No techniques available`
  - `Select an actor to start comparison`
- Disabled compare/save actions when required actors, actor targets, or techniques are missing.
- Centralized global heatmap color/clamp behavior through `comparisonViewUtils.ts`.
- Kept technique parsing, normalization, grouping, and label formatting in `ttpProfileUtils.ts`.
- Replaced text-only graph pan controls with lucide icons.
- Strengthened the sidebar active-state highlight and kept comparison tab styling consistent.

## How To Test

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

Manual smoke test:

1. Open the app and confirm the sidebar shows `Compare`, `TTP Profiles`, `Explore`, and `Settings`.
2. Run an actor comparison from `Compare`.
3. Create, save, inspect, and compare a TTP profile from `TTP Profiles`.
4. Open `Explore` and verify the heatmap and graph modules still render.
