# Iteration 3.7 Part 2 - Saved Analyses UI

## Implemented

The Compare module now includes a `Saved Analyses` section below the live comparison workspace.

Users can:

- browse saved analysis summaries
- inspect a saved analysis in detail
- view saved results through the existing Ranking, Heatmap, and Graph tabs
- delete a saved analysis after confirmation

The section uses the existing backend endpoints:

```text
GET /api/analysis
GET /api/analysis/{id}
DELETE /api/analysis/{id}
```

No backend features or scoring logic were changed.

## Saved Analysis Display

Each saved analysis summary shows:

- input name
- input type: Actor Profile or Custom TTP Profile
- metric
- tactic scope
- top result count
- creation date

The detail view shows the saved metadata and renders the stored comparison payload with the existing comparison result tabs.

## Result Adapter

`frontend/src/api/savedAnalysisUtils.ts` adapts `AnalysisDetail` into the props expected by `ComparisonResultTabs`.

The adapter does not recompute results. It only derives display labels from saved metadata:

- tactic scope label
- target scope label
- metric label
- input type label
- created date label

Saved analysis result tabs are read-only, so the `Save analysis` button is hidden there.

## Delete Flow

The detail panel includes `Delete`.

Deletion:

1. asks for browser confirmation
2. calls `DELETE /api/analysis/{id}`
3. removes the item from the local list
4. selects the next available saved analysis, if one exists

## Empty, Loading, and Error States

The UI includes:

- `No saved analyses yet. Run a comparison and click Save analysis.`
- loading states for the list and selected detail
- API error messages for list, detail, refresh, and delete failures

## Limitations

- Saved analyses cannot be edited.
- Saved analyses cannot be re-run.
- There is no advanced history search or filtering yet.
- OpenCTI and AI features are not included.

## Files Changed

- `frontend/src/api/savedAnalysisUtils.ts`
- `frontend/src/api/savedAnalysisUtils.test.ts`
- `frontend/src/components/ActorComparisonPanel.tsx`
- `frontend/src/components/ComparisonResultTabs.tsx`
- `frontend/src/styles.css`

## Manual Test

1. Open `Compare`.
2. Run a comparison.
3. Click `Save analysis`.
4. Confirm the saved item appears under `Saved Analyses`.
5. Select the saved analysis.
6. Confirm Ranking, Heatmap, and Graph render.
7. Click `Delete`.
8. Confirm the analysis disappears.
9. Refresh the page and confirm deleted analyses stay deleted.

## Validation

Frontend:

```powershell
docker compose run --rm frontend npm run test
docker compose run --rm frontend npm run build
docker compose run --rm frontend npm run lint
```
