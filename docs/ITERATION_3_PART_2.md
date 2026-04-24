# Iteration 3 Part 2 - Matrix Heatmap

## Implemented

- Frontend matrix panel for actor similarity heatmaps.
- Matrix API integration:
  - compute with `POST /api/matrix`
  - retrieve latest with `GET /api/matrix/result`
- Metric selector for:
  - `jaccard`
  - `jaccard_weighted`
  - `tactic_weighted_jaccard`
  - `software_weighted_jaccard`
- Heatmap table with:
  - actor row and column labels
  - color legend
  - score tooltips
  - generated metadata
- Large matrix usability controls:
  - actor name filtering
  - top actor limit
  - capped rendering up to 80 actors
  - scrollable heatmap viewport
- Loading, error, empty, and no-match states.

## How To Test

Start the local stack:

```powershell
docker compose up -d --build backend frontend
```

Load MITRE data if needed:

```powershell
curl.exe -X POST http://localhost:8000/api/source/load
```

Open the frontend:

```text
http://localhost:5173
```

Use the "Actor heatmap" panel:

1. Select a metric.
2. Click "Compute matrix".
3. Adjust "Top actors" to limit the rendered matrix.
4. Use "Filter actors" to narrow rows and columns by name.
5. Click "Retrieve latest" to reload the last backend matrix result.

Frontend validation:

```powershell
cd frontend
npm run build
npm run lint
```

Docker validation:

```powershell
docker compose run --rm frontend npm run build
docker compose run --rm frontend npm run lint
```

## Not Implemented

- clustering
- dendrogram
- network graph
- OpenCTI
- AI
- timeline
