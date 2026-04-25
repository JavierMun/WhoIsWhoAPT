# Iteration 3.5 Part 4 - Comparison Result Views

## Implemented

Actor Comparison results now render as one analysis with three result views:

- Ranking
- Heatmap
- Graph

The tabs appear only after a comparison returns results. Empty comparisons still show a clear empty state without result-view tabs.

## Ranking

The Ranking tab preserves the existing ranked list:

- score
- shared techniques
- unique technique counts
- shared software
- tactic breakdown
- export actions

Exports remain available from the shared comparison result header:

- JSON
- CSV
- ATT&CK Navigator layer

## Heatmap

The comparison heatmap is based only on the current comparison response.

It differs from the global heatmap because:

- it does not call `/api/matrix`
- it does not compute or render the all-vs-all actor matrix
- it shows one source entity row against the currently matched entities
- columns are the current ranked comparison results
- cell values are the result scores from the current comparison

The palette uses red/orange intensity so it feels distinct from the global green matrix view.

The user can limit visible result columns when the comparison contains many matches.

## Graph

The comparison graph is also based only on the current comparison response.

It differs from the global graph because:

- it does not call `/api/matrix`
- it does not call `/api/clusters`
- it does not render actor-to-actor network relationships
- it uses the source actor/profile as the central node
- matched entities are arranged around the source
- edge width reflects the comparison score

Controls:

- similarity threshold
- zoom in
- zoom out
- pan controls
- reset view

## Backend

No backend changes were required for this part.

The existing comparison result payload already contains the score and matched entity data needed for all three views.

## Files

- `frontend/src/api/comparisonViewUtils.ts`
- `frontend/src/api/comparisonViewUtils.test.ts`
- `frontend/src/components/ActorComparisonPanel.tsx`
- `frontend/src/components/ComparisonResultTabs.tsx`
- `frontend/src/components/ComparisonRankingView.tsx`
- `frontend/src/components/ComparisonHeatmapView.tsx`
- `frontend/src/components/ComparisonGraphView.tsx`
- `frontend/src/styles.css`

## Manual Test

Start the stack:

```powershell
docker compose up -d --build backend frontend
```

Open:

```text
http://localhost:5173
```

Test Actor Comparison:

1. Run a normal actor comparison.
2. Confirm the result panel shows Ranking, Heatmap, and Graph tabs.
3. Confirm Ranking still shows the existing result list and export buttons.
4. Open Heatmap.
5. Confirm it shows one source row and matched result columns.
6. Adjust the visible result limit.
7. Open Graph.
8. Adjust the similarity threshold.
9. Use zoom, pan, and reset controls.
10. Confirm Visual Analysis still has the global heatmap and global graph modules.

## Validation Commands

Frontend:

```powershell
docker compose build frontend
docker compose run --rm frontend npm run test
docker compose run --rm frontend npm run build
docker compose run --rm frontend npm run lint
```
