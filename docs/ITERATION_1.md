# Iteration 1 - Core Engine and MITRE

## Implemented

- MITRE ATT&CK Enterprise ingestion into SQLite.
- Normalized actors, campaigns, software, techniques, and sub-techniques.
- Source load and status API:
  - `POST /api/source/load`
  - `GET /api/source/status`
- Actor lookup API:
  - `GET /api/actors`
  - `GET /api/actors/{id}`
- Technique lookup API:
  - `GET /api/techniques`
- Custom TTP set API:
  - `POST /api/custom-sets`
  - `GET /api/custom-sets`
  - `GET /api/custom-sets/{id}`
- Comparison API:
  - `POST /api/compare/actor`
  - `POST /api/compare/custom`
- Similarity metrics:
  - Jaccard
  - Rarity-weighted Jaccard
- Basic explainability in comparison results:
  - shared techniques
  - techniques unique to input
  - techniques unique to matched entity
- Minimal frontend:
  - actor search and comparison
  - custom TTP set creation
  - ATT&CK Navigator JSON import
  - saved custom set comparison
  - loading, error, and empty states

## Not Implemented

- OpenCTI
- AI features
- clustering
- heatmaps and network graphs
- CVE enrichment
- sector or geography enrichment
- tactic-weighted similarity
- campaign/software comparison endpoints

## Run

Start the local stack:

```powershell
docker compose up -d --build backend frontend
```

Open the frontend:

```text
http://localhost:5173
```

## Load MITRE Data

```powershell
curl.exe -X POST http://localhost:8000/api/source/load
```

Check ingestion status:

```powershell
curl.exe http://localhost:8000/api/source/status
```

## Use Actor Comparison

List actors:

```powershell
curl.exe http://localhost:8000/api/actors
```

Compare one actor against all actors:

```powershell
curl.exe -X POST http://localhost:8000/api/compare/actor `
  -H "Content-Type: application/json" `
  -d "{\"actor_id\":\"ACTOR_ID\",\"metric\":\"jaccard\",\"top_n\":10}"
```

## Use Custom TTP Sets

List techniques:

```powershell
curl.exe http://localhost:8000/api/techniques
```

Save a custom set:

```powershell
curl.exe -X POST http://localhost:8000/api/custom-sets `
  -H "Content-Type: application/json" `
  -d "{\"name\":\"Incident TTPs\",\"technique_ids\":[\"T1059\",\"T1105\"]}"
```

Compare an inline custom set:

```powershell
curl.exe -X POST http://localhost:8000/api/compare/custom `
  -H "Content-Type: application/json" `
  -d "{\"name\":\"Incident TTPs\",\"technique_ids\":[\"T1059\",\"T1105\"],\"metric\":\"jaccard\",\"top_n\":10}"
```

Compare a saved custom set:

```powershell
curl.exe -X POST http://localhost:8000/api/compare/custom `
  -H "Content-Type: application/json" `
  -d "{\"custom_set_id\":\"CUSTOM_SET_ID\",\"metric\":\"jaccard_weighted\",\"top_n\":10}"
```

## Navigator Import

The frontend accepts ATT&CK Navigator JSON layer files with a `techniques` array. It reads common technique ID keys such as:

- `techniqueID`
- `techniqueId`
- `technique_id`

Disabled techniques with `"enabled": false` are ignored. Imported IDs are normalized to uppercase and checked against `GET /api/techniques`.

## Test

Backend:

```powershell
cd backend
python -m pytest
python -m ruff check .
python -m mypy app tests
```

Frontend through Docker:

```powershell
docker compose run --rm frontend npm run build
docker compose run --rm frontend npm run lint
```
