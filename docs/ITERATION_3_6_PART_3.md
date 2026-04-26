# Iteration 3.6 Part 3 - Library-First TTP Profiles and Editing

## Implemented

The `TTP Profiles` module now opens as a library-first workspace instead of always showing the creation form.

Default view:

- Profile Library list
- Profile Detail panel
- Custom TTP Profiles first
- Actor Profiles second

The create/edit form is hidden by default and opens only when the user chooses an action.

## Create and Edit Workflow

Custom profile creation starts from `New Custom Profile`.

Custom profile editing starts from the `Edit` action in the detail panel. The same form is reused for create and edit, and edit mode pre-populates:

- name
- description
- selected techniques

The form supports:

- paste technique IDs
- import Navigator JSON
- search/filter/select techniques
- grouped selected techniques by tactic
- unknown technique validation
- normalized technique IDs before save

Create mode uses `Save profile`; edit mode uses `Save changes`. Both modes include `Cancel`.

## Permissions

- Actor Profiles are read-only.
- Custom TTP Profiles can be edited.
- Custom TTP Profiles can be deleted after confirmation.

Actor profile software display and technique grouping are preserved.

## Backend

Two backward-compatible endpoints were added:

```text
PUT /api/custom-sets/{id}
DELETE /api/custom-sets/{id}
```

Existing endpoints continue to work:

```text
POST /api/custom-sets
GET /api/custom-sets
GET /api/custom-sets/{id}
```

No comparison or scoring logic was changed.

## Files Changed

- `backend/app/api/routes/custom_sets.py`
- `backend/tests/test_custom_sets_and_techniques_api.py`
- `frontend/src/api/client.ts`
- `frontend/src/api/ttpProfileUtils.ts`
- `frontend/src/api/ttpProfileUtils.test.ts`
- `frontend/src/components/TTPProfilesPanel.tsx`
- `frontend/src/styles.css`

## Manual Test

1. Open `TTP Profiles`.
2. Confirm the library and detail panel are visible by default.
3. Confirm the create form is hidden.
4. Click `New Custom Profile`.
5. Paste/import/select techniques and save a profile.
6. Select the saved Custom TTP Profile and click `Edit`.
7. Change name, description, and techniques, then click `Save changes`.
8. Confirm Actor Profiles have no Edit or Delete action.
9. Delete a Custom TTP Profile and confirm it disappears from the library.
10. Inspect an Actor Profile and confirm software and grouped techniques still render.

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
