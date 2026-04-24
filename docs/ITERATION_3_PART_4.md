# Iteration 3 Part 4 - Incident Analysis Panel

## Implemented

- Dedicated incident analysis API:
  - `POST /api/analyze/incident`
- Dedicated frontend "Incident Analysis" panel.
- Incident inputs:
  - incident name
  - optional description
  - manually pasted ATT&CK technique IDs
  - ATT&CK Navigator JSON layer import
  - metric selector
  - top result count
- Analyst-friendly results:
  - ranked actor matches
  - score
  - shared techniques
  - rare shared techniques when using rarity-weighted scoring
  - tactic breakdown
  - shared software when present
  - structured "Why this matched" details
- Export from current results:
  - JSON
  - CSV
  - Navigator layer

## Backend Reuse

The new endpoint is a thin wrapper around the existing custom technique comparison flow.
It reuses the same validation, actor candidate loading, scoring, tactic breakdown, and software enrichment logic used by `POST /api/compare/custom`.

No LLM or AI-generated narrative is used.

## Technique Parsing

Frontend manual input accepts ATT&CK technique IDs separated by commas, spaces, tabs, or new lines.

Examples:

```text
T1059, T1105
t1027 T1003.001
```

The frontend parser:

- uppercases IDs
- extracts IDs matching `T####` or `T####.###`
- removes duplicates
- sorts IDs for stable display

The backend also normalizes the submitted list by trimming whitespace, uppercasing IDs, and removing duplicates. Unknown or empty technique sets return clear `422` errors.

## API Example

```powershell
curl.exe -X POST http://localhost:8000/api/analyze/incident `
  -H "Content-Type: application/json" `
  -d "{\"incident_name\":\"Case 42\",\"description\":\"Observed intrusion TTPs\",\"technique_ids\":[\"t1059\",\"T1105\",\"T1059\"],\"metric\":\"jaccard_weighted\",\"top_n\":10}"
```

## UI Workflow

Start the stack:

```powershell
docker compose up -d --build backend frontend
```

Load MITRE data if needed:

```powershell
curl.exe -X POST http://localhost:8000/api/source/load
```

Open:

```text
http://localhost:5173
```

Use the "Incident Analysis" panel:

1. Enter an incident name.
2. Paste ATT&CK technique IDs or import a Navigator JSON layer.
3. Choose the similarity metric.
4. Choose the number of actor matches.
5. Click "Analyze incident".
6. Review "Why this matched" and export results if needed.

## Validation

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
- AI narrative explanations
- timeline
- new clustering algorithms
- new data sources
- SIEM/EDR integrations
