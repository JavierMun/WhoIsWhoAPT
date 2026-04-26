# Iteration 3.7 - Analysis Persistence and Saved Analyses

## Summary

Iteration 3.7 adds local persistence for comparison analyses and a frontend workflow for browsing saved results.

Saved analyses are snapshots. The application stores the comparison result payload that already exists in the UI and does not recompute scores when saving or inspecting a saved analysis.

## Persistence

Saved analyses include:

- input type: `actor` or `custom`
- input ID when available
- input name
- metric
- selected tactics when scoped
- selected target actor IDs when scoped
- `top_n`
- full comparison result JSON
- UTC creation timestamp

## API Endpoints

```text
POST   /api/analysis/save
GET    /api/analysis
GET    /api/analysis/{id}
DELETE /api/analysis/{id}
```

Endpoint behavior:

- `POST /api/analysis/save` stores the supplied result payload without recomputing it.
- `GET /api/analysis` returns summaries only.
- `GET /api/analysis/{id}` returns the full saved payload.
- `DELETE /api/analysis/{id}` removes a saved analysis.
- Missing analyses return `Analysis not found`.
- Corrupt stored result JSON returns `Saved analysis results are invalid`.

## UI Workflow

The Compare result tabs include `Save analysis` for live comparison results.

After saving:

1. the button is disabled while the request is in progress
2. success or error feedback is shown
3. the Saved Analyses list refreshes

The Compare module also includes a `Saved Analyses` section.

Users can:

- view saved analysis summaries
- inspect one saved analysis
- render saved results with Ranking, Heatmap, and Graph tabs
- delete a saved analysis after confirmation

Saved analysis detail views are read-only and do not show `Save analysis` again.

## Hardening

This hardening pass tightened:

- duplicate save click protection
- saved-list refresh behavior after save and delete
- empty, loading, success, and error states
- consistent metadata display for input name, input type, metric, tactics, `top_n`, and creation date
- UTC timestamp serialization from the backend
- backend handling for unknown IDs and malformed stored result JSON
- frontend helper tests for saved-analysis display labels and adapters

## Limitations

- Saved analyses cannot be edited.
- Saved analyses cannot be re-run.
- There is no advanced saved-analysis history search or filtering.
- OpenCTI is not implemented in this iteration.
- AI features are not implemented in this iteration.
- No new scoring logic or data sources were added.

## Manual Test

1. Open `Compare`.
2. Run an actor or custom TTP profile comparison.
3. Click `Save analysis`.
4. Confirm the save button disables while saving and then shows success.
5. Confirm the saved item appears in `Saved Analyses`.
6. Select the saved analysis.
7. Confirm metadata is shown consistently.
8. Confirm Ranking, Heatmap, and Graph render from the saved payload.
9. Confirm the saved detail view does not show `Save analysis`.
10. Delete the saved analysis and confirm the list refreshes.
11. Refresh the page and confirm deleted analyses remain deleted.

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
