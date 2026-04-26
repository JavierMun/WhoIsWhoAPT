# WhoIsWhoAPT v2

## Overview

WhoIsWhoAPT is a threat intelligence analysis tool designed to help analysts understand relationships between threat actors, campaigns, and techniques based on their TTPs (Tactics, Techniques, and Procedures).

The tool enables structured comparison, similarity analysis, and visualization of threat actor behavior using MITRE ATT&CK data and custom-defined profiles.

---

## Problem It Solves

Threat intelligence analysis often requires:

* Comparing threat actors based on behavior rather than labels
* Understanding how an incident aligns with known actors
* Identifying overlaps in techniques across campaigns or groups
* Exploring relationships between actors in a structured way

This process is typically manual, fragmented, and difficult to scale.

WhoIsWhoAPT addresses this by providing a unified framework to:

* Correlate actors using TTPs
* Analyze incidents against known behavior
* Visualize relationships between actors
* Support early-stage attribution and threat hunting

---

## Core Capabilities

### Actor Comparison

* Compare one actor against all or a selected subset
* Multiple similarity metrics:

  * Jaccard
  * Rarity-weighted Jaccard
  * Tactic-weighted Jaccard
  * Software-aware similarity
* Detailed explainability:

  * Shared techniques
  * Unique techniques
  * Tactic breakdown
  * Rare techniques

---

### TTP Profiles

* Create custom profiles from:

  * Manual input
  * Technique selection
  * ATT&CK Navigator import
* Add description and metadata
* Reuse profiles for analysis
* Compare profiles against actors

---

### Tactic-Scoped Analysis

* Filter similarity by specific ATT&CK tactics:

  * Initial Access
  * Execution
  * Persistence
  * Command & Control
  * Collection
  * Exfiltration
* Enables phase-specific analysis

---

### Visual Analysis

#### Ranking View

* Ranked similarity results
* Explainable scoring

#### Heatmap

* Actor-to-actor similarity visualization
* Global similarity matrix
* Color-coded intensity

#### Graph

* Network graph of actor relationships
* Clustering visualization
* Threshold-based filtering
* Interactive (zoom, pan, reset)

---

### Incident Analysis (via TTP Profiles)

* Map observed techniques to known actors
* Identify closest matches
* Support attribution workflows

---

## How It Works

The system follows a simple model:

```
Input → Analysis Engine → Output
```

### Input

* Actor
* TTP Profile (custom or imported)

### Analysis Engine

* Similarity computation
* Technique filtering (optional by tactic)
* Weighting strategies

### Output

* Ranked matches
* Heatmap visualization
* Graph relationships

---

## Architecture

### Backend

* FastAPI (Python)
* SQLAlchemy
* SQLite
* Modular analytics engine

### Frontend

* React + Vite
* Modular component architecture
* D3-based graph visualization

### Data Sources

* MITRE ATT&CK (primary)
* Navigator JSON (custom input)

---

## Current Limitations

* No persistent storage of analysis results
* Single active data source (no merging)
* Limited enrichment (no external intel feeds)
* No multi-user support
* No real-time data ingestion
* No OpenCTI integration yet

---

## Roadmap

### Phase 1 — Consolidation (Completed)

* Unified UI modules
* TTP Profiles
* Comparison views (ranking, heatmap, graph)
* Tactic filtering
* UX improvements

---

### Phase 2 — Persistence

* Save analysis results
* History and re-execution
* Stored graphs and comparisons

---

### Phase 3 — OpenCTI Integration

* Use OpenCTI as data source
* Ingest actors, campaigns, software, CVEs
* Improve data richness

---

### Phase 4 — Intelligence Workflows

* Attribution workflows
* Hunting support
* Campaign clustering

---

### Phase 5 — Advanced Analysis

* Enhanced explainability
* Rare technique insights
* Behavioral pattern detection

---

## Future Vision

WhoIsWhoAPT aims to evolve into a technical threat intelligence platform focused on:

* Behavior-based correlation of threat actors
* Analyst-driven investigation workflows
* Explainable similarity and attribution support

The goal is not to replace existing CTI platforms, but to provide a focused tool for behavioral analysis and actor comparison.

---

## Status

Active development — internal tool in evolution.

---
