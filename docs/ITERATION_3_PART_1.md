# Iteration 3 Part 1 - Actor Similarity Matrix

## Implemented

- Synchronous full actor similarity matrix computation.
- Matrix API:
  - `POST /api/matrix`
  - `GET /api/matrix/result`
- Supported metrics:
  - `jaccard`
  - `jaccard_weighted`
  - `tactic_weighted_jaccard`
  - `software_weighted_jaccard`
- Matrix metadata:
  - `source`
  - `metric`
  - `generated_at`
  - `actor_count`
- Frontend-friendly result structure:
  - `actors`: row/column actor list
  - `matrix`: two-dimensional score array aligned to `actors`

## API Examples

Compute a matrix with the default metric:

```powershell
curl.exe -X POST http://localhost:8000/api/matrix `
  -H "Content-Type: application/json" `
  -d "{}"
```

Compute a matrix with a specific metric:

```powershell
curl.exe -X POST http://localhost:8000/api/matrix `
  -H "Content-Type: application/json" `
  -d "{\"metric\":\"tactic_weighted_jaccard\"}"
```

Retrieve the latest computed matrix:

```powershell
curl.exe http://localhost:8000/api/matrix/result
```

Example response shape:

```json
{
  "metadata": {
    "source": "mitre",
    "metric": "jaccard",
    "generated_at": "2026-04-24T10:00:00Z",
    "actor_count": 2
  },
  "actors": [
    {"id": "ACTOR_A", "name": "Actor A", "source": "mitre"},
    {"id": "ACTOR_B", "name": "Actor B", "source": "mitre"}
  ],
  "matrix": [
    [1.0, 0.42],
    [0.42, 1.0]
  ]
}
```

## Notes

- Computation is synchronous for now.
- The latest matrix result is kept in the backend process memory.
- Scores are normalized between `0` and `1`.
- Empty technique/software evidence follows the existing similarity semantics and scores `0.0`.

## Not Implemented

- heatmap visualization
- dendrogram
- network graph
- clustering
- OpenCTI
- AI
- timeline
