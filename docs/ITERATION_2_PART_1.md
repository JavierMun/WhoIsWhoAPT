# Iteration 2, Part 1 - Tactic-Aware Explainability and Scoring

## Implemented

- Comparison results now include `tactic_breakdown` for each ranked match.
- Shared techniques are grouped by tactic in API responses and frontend result panels.
- Each tactic includes input, matched, shared, and union counts.
- Each tactic includes `score_contribution`, normalized between `0` and `1`.
- Backend settings now include configurable tactic weights:

```json
{
  "scoring": {
    "tactic_weights": {
      "persistence": 2.0,
      "command-and-control": 1.5,
      "exfiltration": 1.5
    }
  }
}
```

- Existing `jaccard` and `jaccard_weighted` behavior is preserved.
- New metric: `tactic_weighted_jaccard`.

## API Usage

Update tactic weights:

```powershell
curl.exe -X PUT http://localhost:8000/api/settings `
  -H "Content-Type: application/json" `
  -d "{\"active_source\":\"mitre\",\"scoring\":{\"tactic_weights\":{\"persistence\":2.0,\"command-and-control\":1.5}}}"
```

Run actor comparison with tactic weighting:

```powershell
curl.exe -X POST http://localhost:8000/api/compare/actor `
  -H "Content-Type: application/json" `
  -d "{\"actor_id\":\"ACTOR_ID\",\"metric\":\"tactic_weighted_jaccard\",\"top_n\":10}"
```

Run custom set comparison with tactic weighting:

```powershell
curl.exe -X POST http://localhost:8000/api/compare/custom `
  -H "Content-Type: application/json" `
  -d "{\"name\":\"Incident TTPs\",\"technique_ids\":[\"T1059\",\"T1105\"],\"metric\":\"tactic_weighted_jaccard\",\"top_n\":10}"
```

## Scoring

For `tactic_weighted_jaccard`, each technique receives the configured weight for its tactic. Missing tactic weights default to `1.0`.

```text
score = weighted shared techniques / weighted union techniques
```

The result remains normalized between `0` and `1` because the numerator is always a subset of the weighted union denominator.

## UI Usage

In actor comparison or custom set comparison:

1. Select `Tactic weighted` in the Metric control.
2. Run the comparison.
3. Each result shows tactic rows with score contribution and shared technique counts.

## Not Implemented

- CVE ingestion
- sector or geography targeting
- OpenCTI
- clustering
- heatmaps
- network graphs
- AI
- timeline
