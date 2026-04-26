# Iteration 3.7 Part 1 - Analysis Persistence

## Implemented

Comparison analyses can now be saved and retrieved without recomputing results.

The backend stores an analysis snapshot containing:

- input type: `actor` or `custom`
- input ID when available
- input name
- metric
- tactic scope when selected
- selected target actor IDs when selected
- top result count
- full comparison result payload as JSON
- UTC creation timestamp

## API Endpoints

New endpoints:

```text
POST /api/analysis/save
GET /api/analysis
GET /api/analysis/{id}
DELETE /api/analysis/{id}
```

`POST /api/analysis/save` stores exactly the comparison payload sent by the frontend. It does not call comparison/scoring code.

## Frontend Save Flow

The comparison result header now includes `Save analysis`.

When clicked, the frontend sends:

- current comparison response
- `input_type`
- `input_id`
- `input_name`
- metric
- selected tactics
- selected actor target IDs
- `top_n`

The UI shows a small success or error message after the save attempt.

## Limitations

- No history browser UI yet.
- Saved analyses cannot be edited.
- Loading a saved analysis into the comparison result tabs is not implemented yet.
- OpenCTI and AI features are not included.

## Files Changed

- `backend/app/models/entities.py`
- `backend/app/models/schemas.py`
- `backend/app/api/routes/analysis.py`
- `backend/app/api/router.py`
- `backend/tests/test_analysis_api.py`
- `frontend/src/api/client.ts`
- `frontend/src/api/types.ts`
- `frontend/src/components/ActorComparisonPanel.tsx`
- `frontend/src/components/ComparisonResultTabs.tsx`
- `frontend/src/styles.css`

## Manual Test

1. Open `Compare`.
2. Run any comparison.
3. Click `Save analysis`.
4. Confirm a success message appears.
5. Check saved summaries:

```powershell
curl.exe http://localhost:8000/api/analysis
```

6. Retrieve one saved detail:

```powershell
curl.exe http://localhost:8000/api/analysis/{id}
```

7. Delete one saved analysis:

```powershell
curl.exe -X DELETE http://localhost:8000/api/analysis/{id}
```

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
