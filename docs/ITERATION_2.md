# Iteration 2 - Enriched Comparison, Explainability, and Export

## Implemented

Iteration 2 is implemented as focused parts on top of the Iteration 1 MITRE comparison engine.

- Tactic-aware explainability for actor and custom-set comparison results.
- Configurable tactic weights in backend settings.
- New opt-in metric: `tactic_weighted_jaccard`.
- MITRE software relationships in actor detail and comparison explainability.
- New opt-in metric: `software_weighted_jaccard`.
- Export of current comparison results as JSON, CSV, and ATT&CK Navigator layer.
- Frontend result panels for actor and custom comparisons show:
  - shared techniques
  - tactic breakdown
  - shared software when available
  - export actions for non-empty result sets

## Metrics

`jaccard`

```text
shared techniques / technique union
```

`jaccard_weighted`

Uses rarity weights derived from actor technique usage:

```text
weighted shared techniques / weighted technique union
```

`tactic_weighted_jaccard`

Uses configured tactic weights. Missing tactic weights default to `1.0`. If a technique is mapped to multiple tactics, the strongest configured tactic weight is used for scoring.

```text
tactic-weighted shared techniques / tactic-weighted technique union
```

`software_weighted_jaccard`

Blends technique Jaccard with software Jaccard only when both compared actors have software observations.

```text
software_score = shared software / software union
score = technique contribution + software contribution
```

If either side has no software relationships, the score falls back to the technique score for that pair.

## Settings

Example scoring settings:

```json
{
  "scoring": {
    "tactic_weights": {
      "persistence": 2.0,
      "command-and-control": 1.5,
      "exfiltration": 1.5
    },
    "technique_score_weight": 0.75,
    "software_score_weight": 0.25
  }
}
```

## Exports

The UI exports from current comparison state and does not recompute scores.

- JSON keeps metadata and the full comparison response.
- CSV writes one row per result and flattens list fields with semicolons.
- Navigator exports unique shared techniques from the current results as an Enterprise ATT&CK layer.

Backend export endpoints are also available for clients that already have comparison results:

```text
POST /api/export/json
POST /api/export/csv
POST /api/export/navigator
```

## API Examples

Actor comparison with tactic weighting:

```powershell
curl.exe -X POST http://localhost:8000/api/compare/actor `
  -H "Content-Type: application/json" `
  -d "{\"actor_id\":\"ACTOR_ID\",\"metric\":\"tactic_weighted_jaccard\",\"top_n\":10}"
```

Actor comparison with software weighting:

```powershell
curl.exe -X POST http://localhost:8000/api/compare/actor `
  -H "Content-Type: application/json" `
  -d "{\"actor_id\":\"ACTOR_ID\",\"metric\":\"software_weighted_jaccard\",\"top_n\":10}"
```

Export already-computed results:

```powershell
curl.exe -X POST http://localhost:8000/api/export/navigator `
  -H "Content-Type: application/json" `
  -d "{\"metadata\":{\"source\":\"mitre\",\"metric\":\"jaccard\",\"generated_at\":\"2026-04-24T10:00:00Z\",\"input_id\":\"ACTOR_ID\",\"input_name\":\"Actor\",\"input_type\":\"actor\",\"top_n\":10},\"comparison\":{\"input_id\":\"ACTOR_ID\",\"input_name\":\"Actor\",\"input_type\":\"actor\",\"metric\":\"jaccard\",\"results\":[]}}"
```

## Test Commands

Backend:

```powershell
cd backend
python -m pytest
python -m ruff check app tests
python -m mypy app tests
```

Frontend:

```powershell
docker compose run --rm frontend npm run build
docker compose run --rm frontend npm run lint
```

## Not Implemented

- OpenCTI
- clustering
- heatmaps
- network graphs
- AI
- timeline
- new data sources
