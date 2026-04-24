# Iteration 3.5 Part 3 - Actor Comparison Target Scope

## Implemented

Actor Comparison now supports two comparison scopes:

- Compare against all actors
- Compare against selected targets

The default remains all actors, preserving the previous behavior.

## Backend

`POST /api/compare/actor` now accepts an optional field:

```json
{
  "actor_id": "ACTOR_ID",
  "metric": "jaccard",
  "top_n": 10,
  "target_ids": ["TARGET_ACTOR_ID"]
}
```

When `target_ids` is omitted, the endpoint compares the source actor against all actors as before.

When `target_ids` is present, the endpoint filters the normal actor candidate list before calling the existing comparison logic. The similarity engine, scoring code, matrix code, and clustering code were not changed.

Validation:

- `target_ids: []` returns a clear 422 error.
- unknown target actor IDs return a clear 422 error with the missing IDs.

## Frontend

`ActorComparisonPanel` now includes:

- a comparison scope selector
- a searchable selected-target picker
- grouped target options for Actors and TTP Profiles
- selected targets displayed as removable chips
- a results summary showing the active target scope

TTP Profile targets are shown in the picker for future-ready UX, but actor comparison currently sends only selected actor IDs to the backend. If only profile targets are selected, the UI asks the user to select at least one actor target.

## Files

- `backend/app/models/schemas.py`
- `backend/app/api/routes/compare.py`
- `backend/tests/test_compare_api.py`
- `frontend/src/api/client.ts`
- `frontend/src/components/ActorComparisonPanel.tsx`
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

1. Leave scope as Compare against all actors.
2. Select a source actor and run comparison.
3. Confirm results behave as before and the result header says `Comparing against: All actors`.
4. Switch to Compare against selected targets.
5. Search for and add one or more actor targets.
6. Run comparison.
7. Confirm only selected actor targets appear in results.
8. Add and remove target chips.
9. Try selected-target mode with no targets and confirm the UI shows an error.
10. Select a TTP Profile target alongside an actor target and confirm comparison still runs against the actor target.
11. Select only a TTP Profile target and confirm the UI explains that actor targets are required for now.

## Validation Commands

Backend:

```powershell
cd backend
python -m pytest tests/test_compare_api.py
```

Frontend:

```powershell
docker compose build frontend
docker compose run --rm frontend npm run test
docker compose run --rm frontend npm run build
docker compose run --rm frontend npm run lint
```
