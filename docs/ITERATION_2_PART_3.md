# Iteration 2, Part 3 - Export Comparison Results

## Implemented

- Export current comparison results as JSON.
- Export current comparison results as CSV.
- Export shared techniques as an ATT&CK Navigator layer.
- Added backend export endpoints:
  - `POST /api/export/json`
  - `POST /api/export/csv`
  - `POST /api/export/navigator`
- Added frontend export buttons to actor and custom comparison result panels.
- Exports include metadata:
  - `source`
  - `metric`
  - `generated_at`
  - input entity or custom set
  - `top_n`

## UI Usage

Run an actor or custom TTP comparison, then use the export buttons in the result header:

- JSON button exports the full comparison payload and metadata.
- CSV button exports one row per result with flattened overlap fields.
- Navigator button exports the shared techniques from the displayed results.

The frontend exports from the current comparison state and does not recompute results.

## API Usage

The export endpoints accept an already-computed comparison payload:

```powershell
curl.exe -X POST http://localhost:8000/api/export/json `
  -H "Content-Type: application/json" `
  -d "{\"metadata\":{\"source\":\"mitre\",\"metric\":\"jaccard\",\"generated_at\":\"2026-04-24T10:00:00Z\",\"input_id\":\"ACTOR_ID\",\"input_name\":\"Actor\",\"input_type\":\"actor\",\"top_n\":10},\"comparison\":{\"input_id\":\"ACTOR_ID\",\"input_name\":\"Actor\",\"input_type\":\"actor\",\"metric\":\"jaccard\",\"results\":[]}}"
```

Use `/api/export/csv` for CSV or `/api/export/navigator` for an ATT&CK Navigator layer.

## Format Details

JSON keeps the full structured comparison response under `comparison` and export metadata under `metadata`.

CSV repeats metadata columns on each result row and flattens list fields with semicolon separators.

Navigator export creates an Enterprise ATT&CK layer with one technique entry per unique shared technique from the exported results. Technique comments list the matched actors that shared the technique.

## Not Implemented

- OpenCTI
- clustering
- heatmaps
- network graphs
- AI
- timeline
