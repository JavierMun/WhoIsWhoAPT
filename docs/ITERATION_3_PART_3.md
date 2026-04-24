# Iteration 3 Part 3 - Clustering and Network Graph

## Implemented

- Backend clustering from the latest actor similarity matrix.
- New cluster endpoint:
  - `GET /api/clusters`
  - optional query: `min_similarity`, default `0.15`
- Frontend actor network graph:
  - nodes are actors
  - edges are actor similarities above the selected threshold
  - node color is the cluster id
  - edge width is the similarity score
  - node tooltip shows actor name and cluster id
- Frontend controls:
  - metric selector
  - similarity threshold slider
  - node limit for large datasets

## Clustering Method

The backend uses average-link hierarchical agglomerative clustering.

This was chosen because the matrix is already pairwise all-vs-all data, and hierarchical clustering works directly from pairwise similarity without needing a fixed number of clusters. Each actor starts as its own cluster. The closest pair of clusters is repeatedly merged while their average similarity is at least `min_similarity`.

The endpoint does not compute a new matrix. It returns `404` until a matrix exists from `POST /api/matrix`.

## Graph Edge Filtering

The frontend builds graph edges from the loaded matrix:

```text
edge exists when similarity > selected_threshold
```

The default threshold is `0.15`. Increasing it shows only stronger relationships. Decreasing it shows a denser graph. Node rendering is capped by the user-selected node limit so the view stays usable for roughly 50-100 actors.

## How To Test

Start the stack:

```powershell
docker compose up -d --build backend frontend
```

Load MITRE data if needed:

```powershell
curl.exe -X POST http://localhost:8000/api/source/load
```

Compute a matrix:

```powershell
curl.exe -X POST http://localhost:8000/api/matrix `
  -H "Content-Type: application/json" `
  -d "{\"metric\":\"jaccard\"}"
```

Get clusters:

```powershell
curl.exe "http://localhost:8000/api/clusters?min_similarity=0.15"
```

Open the frontend:

```text
http://localhost:5173
```

Use the "Actor relationship graph" panel:

1. Select a metric.
2. Adjust the threshold.
3. Set the node limit.
4. Click "Load graph".
5. Hover nodes to see actor names and cluster ids.

Validation:

```powershell
cd backend
python -m pytest
python -m ruff check app tests
python -m mypy app tests
```

```powershell
docker compose run --rm frontend npm run build
docker compose run --rm frontend npm run lint
```

## Not Implemented

- OpenCTI
- AI
- timeline
- advanced graph analytics
