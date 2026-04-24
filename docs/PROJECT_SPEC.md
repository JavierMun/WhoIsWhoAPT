# WhoIsWhoAPT v2 — Project Specification

## Overview

WhoIsWhoAPT is a threat intelligence tool that helps malware analysts, threat hunters and researchers
interrelate APT groups (Advanced Persistent Threats) based on their TTPs (Tactics, Techniques and
Procedures), software, CVEs, and targeting information.

The original project used MITRE ATT&CK as its sole data source and operated as a CLI tool.
Version 2 redesigns the project as a locally-hosted web application with a graphical interface,
multi-source data ingestion, and advanced analytical capabilities.

Original repository for reference: https://github.com/JavierMun/WhoIsWhoAPT

---

## Core Design Decisions

### Single Active Actor Data Source
The application uses a single active **actor data source** at a time.
This source defines the database of actors, campaigns, software, techniques, and related metadata used for comparison.

Supported primary actor data sources:
- MITRE ATT&CK
- OpenCTI

The active actor data source is selected by the user and switching it replaces the currently loaded actor dataset entirely.
There is no merging between primary actor data sources. This eliminates conflict resolution complexity and keeps the data model clean.

This means:
- Some features (e.g., CVE correlation) may only be available when OpenCTI is the active source,
  since MITRE's CVE coverage is sparse.
- The UI must clearly communicate which features are available for the current source.

### Custom TTP Set Inputs
In addition to the active actor data source, the user can create or load **custom TTP sets** that are used as comparison inputs.

Custom TTP sets may come from:
- Manual selection in the application's Navigator-like interface
- Importing local ATT&CK Navigator JSON layer files
- Future: extracting TTPs from OpenCTI reports

Custom TTP sets are stored locally and can be:
- compared against the active actor dataset
- saved for later reuse
- exported/imported as Navigator-compatible files

Custom TTP sets do not replace the active actor data source and are not treated as actor databases.

### Local Hosting
The application runs locally via Docker. No cloud dependency. Data stays on the user's machine.

---

## Architecture

### Stack

| Layer | Technology |
|---|---|
| Backend | Python (FastAPI) |
| Frontend | React + Vite (or similar lightweight SPA) |
| Database | SQLite (local, via SQLAlchemy) |
| Task scheduling | APScheduler or Celery Beat (for auto-updates) |
| Containerization | Docker + Docker Compose |
| MITRE ATT&CK client | `mitreattack-python` library |
| OpenCTI client | `pycti` library |

### Project Structure (proposed)

```
whoiswhoapt/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI entrypoint
│   │   ├── config.py            # Centralized configuration
│   │   ├── models/              # Internal data models (SQLAlchemy + Pydantic)
│   │   │   ├── actor.py
│   │   │   ├── campaign.py
│   │   │   ├── software.py
│   │   │   ├── technique.py
│   │   │   └── cve.py
│   │   ├── sources/             # Data source adapters
│   │   │   ├── base.py          # Abstract base class for all sources
│   │   │   ├── mitre.py
│   │   │   ├── opencti.py
│   │   │   └── navigator.py
│   │   ├── analytics/           # Core comparison and scoring engine
│   │   │   ├── similarity.py
│   │   │   ├── clustering.py
│   │   │   └── explainability.py
│   │   ├── api/                 # FastAPI routers
│   │   │   ├── actors.py
│   │   │   ├── compare.py
│   │   │   ├── settings.py
│   │   │   └── export.py
│   │   ├── scheduler.py         # Auto-update tasks
│   │   └── logging_config.py
│   ├── tests/
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── views/
│   │   ├── components/
│   │   └── api/                 # API client (axios/fetch)
│   └── package.json
├── docker-compose.yml
└── README.md
```

---

## Internal Data Models

These models are the **single source of truth** regardless of which external source is active.
Every source adapter must normalize its data into these models before storing.

```python
# All entities share these base fields
class BaseEntity:
    id: str                  # Internal UUID
    source_id: str           # ID from external source (e.g., MITRE STIX ID)
    source: str              # "mitre" | "opencti" | "navigator"
    name: str
    aliases: list[str]
    description: str | None
    last_updated: datetime

class Actor(BaseEntity):
    """APT group or threat actor"""
    techniques: list[TechniqueRef]     # TTPs with sub-technique support
    campaigns: list[str]               # campaign IDs
    software_used: list[str]           # software IDs
    cves_exploited: list[str]          # CVE IDs (may be empty for MITRE source)
    target_sectors: list[str]
    target_countries: list[str]
    motivation: str | None             # espionage, financial, hacktivism...

class Campaign(BaseEntity):
    """Named operation attributed to one or more actors"""
    actor_ids: list[str]
    techniques: list[TechniqueRef]
    software_used: list[str]
    cves_exploited: list[str]
    start_date: date | None
    end_date: date | None

class Software(BaseEntity):
    """Malware or tool"""
    software_type: str                 # malware | tool
    techniques: list[TechniqueRef]
    actor_ids: list[str]
    campaign_ids: list[str]

class Technique:
    """ATT&CK technique or sub-technique"""
    technique_id: str                  # e.g., T1059 or T1059.001
    name: str
    tactic: str
    is_subtechnique: bool
    parent_id: str | None              # populated if is_subtechnique

class TechniqueRef:
    """Reference to a technique used by an entity"""
    technique_id: str
    use_description: str | None
    detected_in_campaigns: list[str]

class CVE:
    id: str                            # e.g., CVE-2021-44228
    cvss_score: float | None
    affected_products: list[str]
    exploited_by: list[str]            # actor/software IDs
```

---

## Data Sources

### Source Adapter Interface

All source adapters implement the same abstract interface:

```python
class BaseSource(ABC):
    @abstractmethod
    def fetch_actors(self) -> list[Actor]: ...

    @abstractmethod
    def fetch_campaigns(self) -> list[Campaign]: ...

    @abstractmethod
    def fetch_software(self) -> list[Software]: ...

    @abstractmethod
    def fetch_techniques(self) -> list[Technique]: ...

    @abstractmethod
    def get_source_version(self) -> str: ...  # for change detection
```

### Source: MITRE ATT&CK

- Library: `mitreattack-python`
- Data: Groups, Campaigns, Software, Techniques (including sub-techniques)
- Limitations: CVE coverage is sparse. `target_sectors`, `target_countries` and CVEs will be empty
  or partially filled for most actors.
- Version detection: Use ATT&CK version string (e.g., "16.1") to detect when updates are available.

### Source: OpenCTI

- Library: `pycti`
- Requires: OpenCTI instance URL + API token (configured in Settings)
- Data: Full actor profiles including CVEs, targeting, campaigns, and reports
- Report ingestion (optional/advanced): User can search for a specific OpenCTI report by name and
  load its TTPs as a custom set for comparison.

### Input Type: Navigator Layer (local file)

Navigator layer files are not primary actor data sources.
They are auxiliary comparison inputs used to create custom TTP sets.

Use cases:
- Compare an incident-derived TTP set against the active actor dataset
- Save and reuse analyst-defined TTP collections
- Import/export ATT&CK Navigator-compatible JSON files

Multiple Navigator files can be loaded, named, stored locally, and reused as custom sets.
They are always evaluated against the currently active primary actor data source.
---

## Configuration & Settings

Stored in `config.json` (or SQLite settings table). Editable from the UI Settings panel.

```json
{
  "active_source": "mitre",
  "mitre": {
    "auto_update": true,
    "update_frequency_hours": 168
  },
  "opencti": {
    "url": "https://my-opencti-instance.example.com",
    "api_token": "...",
    "auto_update": true,
    "update_frequency_hours": 24
  },
  "ui": {
    "default_top_n": 10,
    "default_similarity_metric": "jaccard_weighted"
  },
  "scoring": {
    "tactic_weights": {
      "persistence": 2.0,
      "command-and-control": 1.5,
      "exfiltration": 1.5
    },
    "technique_score_weight": 0.75,
    "software_score_weight": 0.25
  }
}
```

---

## Analytics Engine

### Similarity Metrics

The engine should support multiple metrics, selectable by the user:

- **Jaccard (baseline):** `|A ∩ B| / |A ∪ B|`
- **Jaccard weighted by rarity:** Techniques used by fewer groups contribute more to the score.
  Weight = `1 / log(1 + count_of_groups_using_technique)`. This surfaces meaningful overlap
  and penalizes ubiquitous techniques.
- **Tactic-weighted Jaccard:** Each tactic (Initial Access, Execution, Persistence...) has a
  configurable weight. Overlap in high-value tactics (e.g., C2, Exfiltration) scores higher.
- **Software-weighted Jaccard:** Optional combined score that blends TTP similarity with software
  overlap when both compared actors have software observations. Missing software relationships do
  not penalize TTP-only comparisons.

The user can configure weights from the UI. Presets for common use cases should be provided
(e.g., "focus on persistence", "focus on initial access").

### Comparison Types

All comparisons return a ranked list with scores and explanation.

| Comparison | Description |
|---|---|
| `actor vs all` | Rank all actors by similarity to a given actor |
| `campaign vs all` | Rank all actors/campaigns by similarity to a given campaign |
| `software vs all` | Rank all actors by overlap with a software's techniques |
| `custom_set vs all` | Rank all actors against a user-defined TTP set |
| `actor vs actor` | Direct comparison between two actors |
| `full similarity matrix` | N×N matrix for all actors (computationally expensive, run async) |

### Explainability

Every comparison result must include a human-readable explanation:

- Which techniques are shared
- Which techniques are unique to each entity
- Which shared techniques are rare (high weight) vs. common (low weight)
- Breakdown by tactic
- (Advanced) LLM-generated narrative summary — see AI Integration section

### Clustering

- Algorithm: DBSCAN (preferred, no need to specify k) or hierarchical clustering
- Input: pairwise similarity matrix for all actors
- Output: cluster labels + dendrogram data + network graph data
- Should be recomputed when the dataset is refreshed

---

## Visualizations

| Visualization | Description |
|---|---|
| Ranked list | Default result view with scores and mini-explanation |
| Heatmap | Color-coded similarity matrix (all vs all) |
| Dendrogram | Hierarchical clustering tree |
| Network graph | Force-directed graph of actor relationships (edge weight = similarity) |
| TTP comparison table | Side-by-side technique listing for two actors, color-coded by overlap |
| Custom Navigator view | Simplified ATT&CK matrix to build/visualize custom TTP sets |

---

## Custom TTP Sets (Navigator-like feature)

A section of the UI where users can:

1. Browse the ATT&CK matrix and select techniques manually
2. Import from a Navigator `.json` file
3. Import from an OpenCTI report (if OpenCTI is the active source)
4. Name and save custom sets for reuse
5. Compare a saved custom set against the actor database

Custom sets are stored locally in the database. They are not tied to a specific actor.

---

## AI Integration

### Explainability (Priority 3)

Use an LLM (via Anthropic API or local model) to generate narrative explanations of comparison
results. The prompt provides the structured comparison data (shared TTPs, unique TTPs, scores by
tactic) and asks for a paragraph summarizing why the similarity is high or low and what that
might imply for attribution or threat hunting.

### Enrchment (Priority 5 / experimental)

Given an actor profile with limited data, query the LLM to suggest:
- Likely missing techniques based on known TTPs and actor profile
- Possible connections to other actors not captured in the current dataset

This is flagged as experimental and must be clearly labeled as AI-generated inference, not
ground truth.

---

## Feature Availability by Source

| Feature | MITRE | OpenCTI | Navigator |
|---|---|---|---|
| Actor profiles | ✅ | ✅ | ❌ (custom sets only) |
| Campaign data | ✅ | ✅ | ❌ |
| Software data | ✅ | ✅ | ❌ |
| Sub-techniques | ✅ | ✅ | ✅ |
| CVE correlation | ⚠️ sparse | ✅ | ❌ |
| Target sectors/geo | ⚠️ sparse | ✅ | ❌ |
| Report ingestion | ❌ | ✅ | ❌ |
| Auto-update | ✅ | ✅ | ❌ |

The UI must display a notice when the user tries to access a feature not supported by the active source.

---

## Implementation Roadmap

### Iteration 0 — Foundation
**Goal:** Clean base to build on. No user-visible features yet.

- Define all internal data models (SQLAlchemy + Pydantic schemas)
- Set up FastAPI project structure with routers, dependency injection, config loading
- Set up React frontend scaffold (just a shell, no real UI)
- Implement centralized logging (structured logs, configurable level)
- Implement global error handling (FastAPI exception handlers, frontend error boundaries)
- Docker + Docker Compose setup (backend + frontend + shared volume for DB)
- CI skeleton: linting (ruff, black), type checking (mypy)

**Exit criteria:** `docker compose up` starts both services, logs appear, health endpoint returns 200.

### Iteration 1 — Core Engine + MITRE
**Goal:** Working comparison engine with real data. CLI-equivalent functionality behind an API.

- Implement MITRE source adapter (groups, campaigns, software, techniques, sub-techniques)
- Database ingestion pipeline (fetch → normalize → store)
- Similarity engine: Jaccard baseline + weighted by rarity
- Comparison endpoints: actor vs all, actor vs actor, custom set vs all
- Navigator file import (for custom sets)
- Unit tests for similarity engine (edge cases: empty sets, identical sets, disjoint sets)
- Basic frontend: source selector, actor search, comparison results as ranked list

**Exit criteria:** User can select MITRE, load data, search for an actor, compare it against all others, and see a ranked list of results in the browser.

### Iteration 2 — Enriched Data + Explainability
**Goal:** More data dimensions and human-readable results.

- Software used and CVE data ingestion (from MITRE where available)
- Target sector/geo data ingestion
- Tactic-weighted similarity metric
- Configurable weights UI
- Explainability: per-result breakdown (shared TTPs, unique TTPs, by tactic)
- Campaign vs all comparison
- Software vs all comparison
- Export: JSON, CSV, ATT&CK Navigator layer
- Settings panel in UI (source config, update frequency, metric config)

**Exit criteria:** User can compare a campaign against all actors, see which techniques are driving the score, and export the result as a Navigator layer.

### Iteration 3 — Visualizations + Clustering
**Goal:** Visual analysis capabilities.

- Full similarity matrix computation (async job with progress indicator)
- Heatmap visualization
- Dendrogram visualization
- Network graph visualization (force-directed)
- Clustering (DBSCAN) with cluster labels on network graph
- TTP comparison table (side-by-side for two actors)
- Custom Navigator-like matrix view for building custom sets

**Exit criteria:** User can generate a full similarity matrix, see clusters on a network graph, and explore relationships visually.

### Iteration 4 — OpenCTI Integration
**Goal:** Full OpenCTI support as an alternative data source.

- OpenCTI source adapter (actors, campaigns, software, CVEs, targeting)
- OpenCTI connection configuration (URL + token) in settings
- Auto-update scheduler for OpenCTI
- Report search and TTP ingestion from OpenCTI reports (as custom sets)
- Feature availability notices in UI (for features not in current source)

**Exit criteria:** User can switch to OpenCTI source, get full actor profiles with CVEs and targeting data, and import TTPs from a specific report.

### Iteration 5 — AI Features (Experimental)
**Goal:** AI-assisted analysis.

- LLM narrative explanation of comparison results (via Anthropic API)
- Configuration for AI features (API key, model selection, on/off toggle)
- Timeline view of TTP evolution per actor (requires campaign date data)
- AI-based enrichment suggestions (clearly labeled as inference, not ground truth)

**Exit criteria:** User can request an AI explanation for any comparison result and see a narrative paragraph alongside the structured data.

---

## API Endpoints (Reference)

```
GET  /api/health
GET  /api/settings
PUT  /api/settings

POST /api/source/load              # trigger ingestion for active source
GET  /api/source/status            # ingestion status, last updated, record counts

GET  /api/actors                   # list all actors
GET  /api/actors/{id}              # actor detail
GET  /api/campaigns
GET  /api/campaigns/{id}
GET  /api/software
GET  /api/software/{id}

POST /api/compare/actor            # actor vs all (or vs actor)
POST /api/compare/campaign         # campaign vs all
POST /api/compare/software         # software vs all
POST /api/compare/custom           # custom set vs all

POST /api/custom-sets              # save a custom TTP set
GET  /api/custom-sets
DELETE /api/custom-sets/{id}

POST /api/matrix                   # trigger full matrix computation (async)
GET  /api/matrix/status
GET  /api/matrix/result

GET  /api/clusters                 # clustering result

POST /api/export/navigator         # export result as Navigator layer
POST /api/export/csv
POST /api/export/json

Export endpoints accept already-computed comparison results and format them without recomputing scores.

POST /api/ai/explain               # LLM explanation for a comparison result (Iter 5)
```

---

## Testing Strategy

- **Unit tests (pytest):** Similarity engine, data model validation, source adapter normalization
- **Integration tests:** API endpoints against a seeded test database
- **Source adapter tests:** Mock external APIs (MITRE TAXII, OpenCTI GraphQL) with fixture data
- **Frontend:** Component tests for critical UI flows (source selection, comparison, export)
- Coverage target: >80% for analytics and source adapter modules

---

## Non-Goals (out of scope for v2)

- Multi-user support / authentication
- Cloud hosting or SaaS deployment
- Real-time streaming of threat intel feeds
- IOC (indicator of compromise) management
- Integration with SIEM or EDR platforms (future v3 consideration)
