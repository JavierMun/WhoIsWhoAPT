# Iteration 3 - Visual Analysis and Incident Workflow

## Implemented

Iteration 3 adds matrix-based visual analysis and a focused incident workflow on top of the existing MITRE comparison engine.

### Part 1 - Actor Similarity Matrix

- `POST /api/matrix` computes the all-vs-all actor matrix synchronously.
- `GET /api/matrix/result` returns the latest in-process matrix result.
- Supported metrics:
  - `jaccard`
  - `jaccard_weighted`
  - `tactic_weighted_jaccard`
  - `software_weighted_jaccard`
- Matrix responses include:
  - source
  - metric
  - generated timestamp
  - actor count
  - actor row/column list
  - normalized score matrix

### Part 2 - Heatmap

- Frontend heatmap panel for the latest actor similarity matrix.
- Metric selector.
- Actor name filter.
- Top actor limit, capped to keep large matrices readable.
- Scrollable heatmap with row/column labels and score tooltips.

### Part 3 - Clustering and Network Graph

- `GET /api/clusters` returns cluster labels from the latest matrix.
- Clustering uses average-link hierarchical agglomerative clustering.
- Frontend force-directed actor network graph:
  - nodes are actors
  - node color is cluster id
  - edges are similarities above the selected edge threshold
  - edge width reflects similarity
  - graph JSON export is available
- Dense graphs are capped to the strongest rendered edges.

### Part 4 - Incident Analysis

- `POST /api/analyze/incident` analyzes observed incident TTPs against all actors.
- Reuses the same scoring and validation logic as custom TTP set comparison.
- Frontend incident panel supports:
  - incident name
  - optional description
  - pasted technique IDs
  - ATT&CK Navigator JSON import
  - metric and top-N selection
  - JSON, CSV, and Navigator exports
- Results show:
  - ranked actor matches
  - score
  - shared techniques
  - rare shared techniques where available
  - tactic breakdown
  - shared software where available
  - structured "Why this matched" details

## Hardening Notes

- Matrix generation mirrors pair scores so all metrics remain exactly symmetric.
- Matrix and clustering coverage now includes all metrics, empty matrices, and single-actor matrices.
- Graph edge filtering is isolated in a typed utility and caps very dense graphs to the strongest edges.
- The graph reuses the latest matrix when the selected metric matches, and computes a matrix only when needed.
- Incident analysis returns clear errors for empty or unknown technique sets.

## API Testing

Compute a matrix:

```powershell
curl.exe -X POST http://localhost:8000/api/matrix `
  -H "Content-Type: application/json" `
  -d "{\"metric\":\"jaccard_weighted\"}"
```

Retrieve the latest matrix:

```powershell
curl.exe http://localhost:8000/api/matrix/result
```

Retrieve clusters:

```powershell
curl.exe "http://localhost:8000/api/clusters?min_similarity=0.15"
```

Analyze an incident:

```powershell
curl.exe -X POST http://localhost:8000/api/analyze/incident `
  -H "Content-Type: application/json" `
  -d "{\"incident_name\":\"Case 42\",\"technique_ids\":[\"t1059\",\"T1105\"],\"metric\":\"jaccard_weighted\",\"top_n\":10}"
```

## UI Testing

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

Test these panels:

1. Actor heatmap:
   - select a metric
   - compute matrix
   - filter actors
   - adjust top actor limit
2. Actor relationship graph:
   - select a metric
   - adjust edge threshold
   - adjust node limit
   - load graph
   - export graph JSON
3. Incident Analysis:
   - paste IDs separated by commas, spaces, or new lines
   - import Navigator JSON
   - run analysis
   - review "Why this matched"
   - export JSON, CSV, or Navigator layer

## Validation Commands

Backend:

```powershell
cd backend
python -m pytest
python -m ruff check app tests
python -m mypy app tests
```

Frontend:

```powershell
docker compose build frontend
docker compose run --rm frontend npm run test
docker compose run --rm frontend npm run build
docker compose run --rm frontend npm run lint
```

## Not Implemented

- OpenCTI
- AI
- timeline
- new data sources
