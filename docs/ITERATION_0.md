# Iteration 0 Foundation

This scaffold adds the local web application base described in `docs/PROJECT_SPEC.md`.

## Services

- `backend`: FastAPI service with `/api/health` and `/api/settings`.
- `frontend`: Vite React shell that checks backend health.
- `whoiswhoapt-data`: Docker volume mounted at `/data` for SQLite and `config.json`.

## Local Docker Run

```powershell
docker compose up --build
```

Backend health:

```powershell
Invoke-RestMethod http://localhost:8000/api/health
```

Frontend:

```text
http://localhost:5173
```

## Deliberately Out Of Scope

The scaffold does not implement MITRE ingestion, OpenCTI integration, similarity scoring, custom set comparison, or AI features.

