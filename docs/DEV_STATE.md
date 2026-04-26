# DEV STATE

## Current Status

Project: WhoIsWhoAPT v2
Stage: Post Iteration 3.7 (Persistence implemented and hardened)

The system is now a functional CTI analysis tool with:

* Actor and TTP profile comparison
* Custom TTP profile creation/editing
* Tactic-scoped similarity
* Multiple similarity metrics
* Visualizations (ranking, heatmap, graph)
* Analysis persistence (save, list, inspect, delete)

---

## Current Architecture

### Backend

* FastAPI
* SQLite
* Modular analytics engine
* Entities:

  * Actor (MITRE)
  * Custom TTP Profile
  * Analysis (new)

### Frontend

* React + Vite
* Modular layout:

  * Compare
  * TTP Profiles
  * Explore
  * Settings

---

## Product Model

Key abstraction:

> A "TTP Profile" represents any entity defined by techniques.

Types:

* Actor profile (MITRE/OpenCTI future)
* Custom TTP profile

Comparison model:

```text
Source Profile → Compare → Target Profiles → Results
```

---

## Completed Iterations

### Iteration 3.5

* Modular UI
* Unified Compare views
* TTP Profiles consolidation

### Iteration 3.6

* Cleanup and naming consistency
* TTP Profiles as a library
* Unified profile selectors in Compare
* Custom profile CRUD (create/edit/delete)

### Iteration 3.7

* Analysis persistence
* Saved Analyses UI
* Hardening (UX + backend validation)

---

## Current Capabilities

* Compare actor vs actors
* Compare custom profile vs actors
* Tactic filtering
* Multiple scoring models
* Explainability (shared, unique, tactic breakdown)
* Save analysis results
* Inspect saved analyses
* Delete saved analyses

---

## Known Limitations

* No OpenCTI integration yet
* Single data source (MITRE only)
* No enrichment
* No re-run of saved analyses
* No multi-user support
* No authentication

---

## Next Step (IMPORTANT)

Next iteration:

### Iteration 4 — OpenCTI MVP (read-only integration)

Goal:

* Use OpenCTI as a data source instead of only MITRE
* Ingest:

  * Actors
  * Campaigns (optional)
  * Software
* Map OpenCTI entities to TTP Profiles

Constraints:

* Read-only integration
* No sync complexity
* No background jobs
* Do not break current MITRE flow

---

## Development Rules

* Do NOT break existing comparison flows
* Do NOT change scoring logic unless necessary
* Reuse existing abstractions (TTP Profile)
* Keep UI modular
* Prefer minimal backend changes
* Maintain backward compatibility

---

## Testing

Backend:

* Run: python -m pytest (from backend directory)

Frontend:

* docker compose run --rm frontend npm run test
* docker compose run --rm frontend npm run build
* docker compose run --rm frontend npm run lint

---

## Notes

The project is transitioning from a prototype into a structured CTI tool.

Focus is now on:

* Data integration (OpenCTI)
* Real-world workflows
* Stability over feature expansion
