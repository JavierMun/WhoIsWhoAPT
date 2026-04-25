# Iteration 3.5 Part 5 - Tactic-Scoped Similarity Filtering

## Implemented

Actor Comparison can now compute similarity over a selected ATT&CK tactic instead of always using every technique attached to the source and matched actors.

The default remains `All tactics`, preserving the previous behavior and request payloads.

## Backend

`POST /api/compare/actor` accepts an optional `tactics` list:

```json
{
  "actor_id": "ACTOR_ID",
  "metric": "jaccard",
  "top_n": 10,
  "tactics": ["initial-access"]
}
```

The comparison endpoint also accepts the same optional field for existing custom/profile-style comparison requests, but no new profile-as-source workflow was added.

## Filtering

Filtering is applied before scoring:

1. Load the source technique set and candidate actor technique sets as before.
2. Load local technique metadata from the `techniques` table.
3. Normalize requested tactic names by trimming and lowercasing.
4. Filter both the source and each candidate technique set to techniques whose tactic metadata matches the selected scope.
5. Pass the filtered sets into the existing comparison functions.

Core similarity functions were not modified, and scoring logic is not duplicated.

## Tactic Mapping

The tactic map is built from existing technique metadata:

```text
Technique.technique_id -> Technique.tactic
```

Technique tactic values can be single values or comma-separated values. A technique is retained when any tactic in its metadata matches any selected tactic.

## Empty Results

If tactic filtering leaves the source side, matched side, or both sides with no techniques, the result score is `0` and the result includes an `explanation` field such as:

```text
No source or matched entity techniques remain after applying tactic scope: exfiltration.
```

## Frontend

`ActorComparisonPanel` now includes a `Similarity scope` selector:

- All tactics
- One tactic derived from `GET /api/techniques`

Selected tactics are included in the actor comparison request. Results show the active filter:

```text
Similarity scope: Initial Access
```

The Ranking, Heatmap, and Graph tabs all use the same filtered comparison response, so they respect the selected scope without additional visualization-specific logic.

## Testing

Backend coverage was added for:

- single tactic filtering
- multiple tactic filtering
- empty filtered results with a clear explanation

Validation commands:

```powershell
cd backend
python -m pytest tests/test_compare_api.py
python -m pytest
```

Frontend validation:

```powershell
docker compose run --rm --no-deps frontend npm run test
docker compose run --rm --no-deps frontend npm run build
docker compose run --rm --no-deps frontend npm run lint
```
