# WhoIsWhoAPT

A threat intelligence analysis tool for comparing threat actors and TTP profiles using behavioral similarity.

Analysts use it to answer: *"Which known groups behave most like this incident?"* — without relying on labels, reporting bias, or manual cross-referencing.

---

## Features

**Compare** — rank threat actors by behavioral similarity to any input profile:
- Multiple metrics: Jaccard, Weighted Jaccard, Tactic-weighted, Software-weighted, Holistic
- Tactic-scoped analysis (filter by Initial Access, Execution, Persistence…)
- Auto-generated insight per result (top tactics, shared sectors, rare techniques)
- Enrichment filter: pre-filter candidates by sector or country before scoring
- Technique breakdown: shared / input-only / target-only, collapsible per row

**TTP Profiles** — build custom profiles and compare them like any actor:
- Manual entry, ATT&CK Navigator import, or OpenCTI report import
- Enrichment metadata: target sectors, countries, CVEs, motivation
- Save and reuse across analyses

**Explore** — global similarity analysis across all actors:
- Similarity heatmap with PNG export
- Force-directed network graph with zoom, pan, drag
- All-vs-all pair ranking with threshold slider
- Enrichment filtering on graph and heatmap

**Saved Analyses** — persist and revisit comparison results:
- Save with name, re-run, inspect, delete
- Paginated list with enrichment filter badge

**Data sources**:
- MITRE ATT&CK (built-in, auto-loaded on first run)
- OpenCTI (optional, configure URL + API token in Settings)

---

## Quick Start

### Requirements

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose

### Run

```bash
git clone https://github.com/YOUR_USERNAME/WhoIsWhoAPT.git
cd WhoIsWhoAPT
docker compose up --build
```

Open **http://localhost:5173** in your browser.

On first startup the backend automatically downloads and ingests the MITRE ATT&CK dataset (~30 seconds). No manual data loading needed.

---

## Configuration

All configuration is via environment variables (see `.env.example`).

| Variable | Default | Description |
|---|---|---|
| `WHOISWHOAPT_ENVIRONMENT` | `development` | Runtime environment |
| `WHOISWHOAPT_LOG_LEVEL` | `INFO` | Log verbosity |
| `WHOISWHOAPT_DATABASE_URL` | `sqlite:////data/whoiswhoapt.db` | SQLite path (inside container) |
| `WHOISWHOAPT_SETTINGS_FILE` | `/data/config.json` | Persisted settings path |
| `WHOISWHOAPT_CORS_ORIGINS` | `["http://localhost:5173"]` | Allowed frontend origins |

To override, copy `.env.example` to `.env` and edit before running `docker compose up`.

### OpenCTI (optional)

In the app, go to **Settings → Source → OpenCTI** and enter your instance URL and API token. Click **Test connection** then **Save**, then **Load data**.

The tool supports OpenCTI 7.x with pycti `7.260430.0`.

---

## Architecture

```
frontend/     React + Vite + TypeScript (port 5173)
backend/      FastAPI + SQLite (port 8000)
```

The frontend proxies API calls to the backend at startup; no manual API URL configuration needed for local Docker use.

**Backend stack:** FastAPI · SQLAlchemy · SQLite · mitreattack-python · pycti · APScheduler

**Frontend stack:** React · Vite · TypeScript · D3-force · Lucide

---

## Development (without Docker)

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
VITE_API_BASE_URL=http://localhost:8000 npm run dev
```

The `VITE_API_BASE_URL` variable is needed outside Docker so the frontend reaches the local backend directly (in Docker it's proxied automatically).

### Tests

```bash
cd backend
pytest
```

```bash
cd frontend
npm run build   # type-check + build
npm run lint
```

---

## License

See [LICENSE](LICENSE).
