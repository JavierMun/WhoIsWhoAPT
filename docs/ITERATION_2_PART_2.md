# Iteration 2, Part 2 - Software Support in Comparison and Explainability

## Implemented

- MITRE software relationships are covered for actor and campaign `uses` links where available.
- Actor detail responses now include resolved software details:
  - `software_used`
  - `software_count`
- Comparison results now include software explainability:
  - `shared_software`
  - `unique_to_input_software`
  - `unique_to_matched_entity_software`
  - `technique_score`
  - `software_score`
  - score contribution fields
- Existing metrics are preserved:
  - `jaccard`
  - `jaccard_weighted`
  - `tactic_weighted_jaccard`
- New opt-in metric: `software_weighted_jaccard`.
- Frontend actor and custom comparison panels display shared software when present.

## API Usage

Get actor details with software:

```powershell
curl.exe http://localhost:8000/api/actors/ACTOR_ID
```

Run actor comparison with software weighting:

```powershell
curl.exe -X POST http://localhost:8000/api/compare/actor `
  -H "Content-Type: application/json" `
  -d "{\"actor_id\":\"ACTOR_ID\",\"metric\":\"software_weighted_jaccard\",\"top_n\":10}"
```

Configure component weights:

```powershell
curl.exe -X PUT http://localhost:8000/api/settings `
  -H "Content-Type: application/json" `
  -d "{\"active_source\":\"mitre\",\"scoring\":{\"technique_score_weight\":0.75,\"software_score_weight\":0.25}}"
```

## Scoring

For `software_weighted_jaccard`, the technique score is the normal Jaccard score over ATT&CK techniques.
The software score is Jaccard over software IDs:

```text
software_score = shared software / software union
```

The final score is a weighted blend:

```text
score = technique_score contribution + software_score contribution
```

Software is optional. If either side has no software relationships, the software component is ignored and the result falls back to the TTP score for that pair.

## UI Usage

In actor comparison or custom set comparison:

1. Select `Software weighted` in the Metric control.
2. Run the comparison.
3. Result rows show `Shared software` when the comparison has overlapping software evidence.

Custom TTP sets do not currently include software input, so software overlap is usually empty there unless future custom-set software support is added.

## Not Implemented

- CVE ingestion beyond existing placeholders
- sector or geography targeting
- OpenCTI
- clustering
- heatmaps
- network graphs
- AI
- timeline
