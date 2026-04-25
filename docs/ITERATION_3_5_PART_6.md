# Iteration 3.5 Part 6 - Final UX Fixes and Technique Readability

## Implemented

This part improves readability and visualization polish without changing backend scoring, clustering, matrix computation, data sources, or comparison algorithms.

## Files Changed

- `frontend/src/api/ttpProfileUtils.ts`
- `frontend/src/api/ttpProfileUtils.test.ts`
- `frontend/src/api/exportUtils.ts`
- `frontend/src/components/ActorComparisonPanel.tsx`
- `frontend/src/components/ComparisonResultTabs.tsx`
- `frontend/src/components/ComparisonRankingView.tsx`
- `frontend/src/components/TTPProfilesPanel.tsx`
- `frontend/src/components/IncidentAnalysisPanel.tsx`
- `frontend/src/components/CustomTTPSetPanel.tsx`
- `frontend/src/components/ActorMatrixHeatmapPanel.tsx`
- `frontend/src/components/ActorNetworkGraphPanel.tsx`
- `frontend/src/styles.css`

## Technique Names

Technique readability now uses metadata from the existing `GET /api/techniques` response.

The frontend builds a local lookup:

```text
technique_id -> TechniqueListItem
```

Shared helpers in `ttpProfileUtils.ts` resolve display labels:

```text
T1059 — Command and Scripting Interpreter
T1059.001 — PowerShell
```

When metadata is unavailable, the UI falls back to the raw technique ID so old comparison payloads still render safely.

Technique labels are shown in:

- Actor Comparison ranking results
- TTP Profile selected-technique chips
- TTP Profile inspection
- TTP Profile comparison results
- Incident Analysis result explanations
- legacy Custom TTP Set result explanations
- CSV comparison exports when the current UI has technique metadata available

Tooltips include tactic details where practical.

## Heatmap Palette

The global actor matrix heatmap now uses a red/orange threat-style palette instead of green.

Dense heatmap cells no longer force text when many actors are visible. Exact values remain available in each cell tooltip as both rounded percentage and decimal score.

## Graph Zoom and Pan

The global actor network graph now includes viewport controls:

- zoom in
- zoom out
- reset view
- pan left/right/up/down

These controls apply only an SVG transform around the rendered graph. Existing threshold, node limit, matrix loading, clustering, and export behavior are unchanged.

Reset restores:

```text
zoom = 1
pan = { x: 0, y: 0 }
```

The viewport also resets when graph data changes.

## Manual Test

Start the stack:

```powershell
docker compose up -d --build backend frontend
```

Open:

```text
http://localhost:5173
```

Test:

1. Actor Comparison
   - Run a comparison.
   - Confirm Ranking shows technique names beside IDs.
   - Hover technique labels and confirm tactic details appear.
   - Confirm Heatmap and Graph tabs still switch correctly.
2. TTP Profiles
   - Search, add, save, inspect, and compare a profile.
   - Confirm selected chips and profile inspection show `ID — name`.
   - Export CSV and confirm shared technique values include names.
3. Visual Analysis
   - Compute or retrieve the global heatmap.
   - Confirm the palette is red/orange and cell tooltips include exact scores.
   - Load the global graph.
   - Use zoom, pan, and reset controls.
   - Confirm threshold and node limit still work.

## Validation

Frontend:

```powershell
docker compose run --rm --no-deps frontend npm run test
docker compose run --rm --no-deps frontend npm run build
docker compose run --rm --no-deps frontend npm run lint
```

Backend tests are not required for this part because backend behavior was not changed.
