# WhoIsWhoAPT — Design Brief for Frontend Redesign

## What is this app?

A **CTI (Cyber Threat Intelligence) analysis tool** for comparing threat actor TTP profiles (MITRE ATT&CK techniques). Analysts use it to compare actors, explore similarity clusters, and identify overlaps between threat groups. The audience is security professionals — the UI should feel **analytical and professional**, not consumer-y.

---

## Tech stack

- **React + Vite** (TypeScript)
- **Plain CSS** — one file: `frontend/src/styles.css` (~1900 lines). No Tailwind, no CSS-in-JS, no component libraries.
- **lucide-react** for icons (already installed)
- **d3-force** for the network graph (keep untouched)

---

## Current color palette

| Role | Value |
|------|-------|
| Primary green (actions, highlights) | `#136f63` |
| Primary green dark | `#0d704f` |
| Background | `#f2f5f7` |
| Panel background | `#fff` |
| Border | `#d9e0e3` / `#e4eaed` |
| Text primary | `#26343d` |
| Text secondary | `#52606a` |
| Text muted | `#70808a` |
| Error red | `#b42318` |
| Success green | `#0d704f` on `#e3f2ed` |

The green palette is intentional (CTI / security tool aesthetic). You can evolve the palette but keep it professional and dark-green anchored.

---

## Application modules (4 sections)

### 1. Compare (`ActorComparisonPanel.tsx` + `ComparisonResultTabs.tsx` + `ComparisonRankingView.tsx`)
The main workspace. Left panel = configuration (source profile, target scope, metric, tactic filter). Right panel = results.

Results show:
- Ranked list of matched actors with score
- Per-result: shared technique count, breakdown panel (3-column collapsible), tactic bars, shared targeting, actor context

### 2. TTP Profiles (`TTPProfilesPanel.tsx`)
Library of saved custom TTP sets + actor profiles. Left = profile list. Right = profile inspector (technique groups by tactic, enrichment tags).

### 3. Explore (`ActorMatrixHeatmapPanel.tsx` + `ActorNetworkGraphPanel.tsx`)
Two panels stacked vertically:
- **Heatmap** — similarity matrix grid with color gradient cells
- **Network graph** — D3 force-directed graph with cluster coloring

### 4. Settings (`SettingsPanel.tsx`)
Data source configuration (MITRE ATT&CK or OpenCTI). Connection test, save, load data, status panel.

---

## Layout structure

```
┌─────────────────────────────────────────────────────┐
│  Sidebar (left, fixed)  │  Main content (right)      │
│  - App logo/name        │  Active module renders here │
│  - Nav: Compare /       │                            │
│    TTP Profiles /       │                            │
│    Explore /            │                            │
│    Settings             │                            │
│  - Backend status strip │                            │
└─────────────────────────────────────────────────────┘
```

The sidebar lives in `Layout.tsx` + `Sidebar.tsx`. The main content area uses `.comparison-workspace` as its root class.

---

## Key CSS classes to understand

```
.comparison-workspace     — full-height module wrapper
.comparison-layout        — two-column grid (controls + results)
.control-panel            — left configuration panel
.results-panel            — right results panel
.workspace-header         — top bar with title + source pill
.result-list              — ordered list of comparison results
.result-row               — single result item
.result-main              — content area inside a result row
.result-meta              — summary line (N shared TTPs · X-only · Y-only)
.result-title-line        — actor name + score
.tactic-breakdown         — tactic bars grid inside a result
.tactic-row               — single tactic bar
.breakdown-panel          — collapsible technique breakdown
.breakdown-columns        — 3-column grid (input-only / shared / target-only)
.breakdown-col            — single column
.source-profile-panel     — collapsible source actor details
.shared-context-row       — green row showing shared sectors/countries
.actor-context-body       — matched actor profile (sectors, countries, CVEs)
.field-group              — label + input pair
.scope-selector           — radio button fieldset
.primary-action           — primary button (green)
.secondary-action         — secondary button (outline)
.technique-chip           — small tag/badge
.source-pill              — top-right badge in headers
.panel-label              — small uppercase section label
.eyebrow                  — tiny category label above headings
.status-message           — info/success/error banner
  .neutral / .success / .error
.metric-label             — similarity metric badge
.backend-strip            — bottom footer bar
```

---

## Files you CAN freely modify

| File | What it contains |
|------|-----------------|
| `frontend/src/styles.css` | All CSS — the main target |
| `frontend/src/components/Layout.tsx` | App shell, sidebar nav |
| `frontend/src/components/Sidebar.tsx` | Navigation sidebar |
| `frontend/src/components/*.tsx` | JSX structure and className assignments |
| `frontend/src/App.tsx` | Root component (minimal) |

When editing component files: **you may change JSX structure, classNames, and inline styles**. Do not change function logic, state, or API calls.

---

## Files you must NOT touch

| File | Why |
|------|-----|
| `frontend/src/api/client.ts` | API calls |
| `frontend/src/api/types.ts` | TypeScript types |
| `frontend/src/api/ttpProfileUtils.ts` | Business logic |
| `frontend/src/api/ttpProfileUtils.ts` | Utilities |
| `frontend/src/api/savedAnalysisUtils.ts` | Saved analysis logic |
| `frontend/src/api/comparisonViewUtils.ts` | Comparison utilities |
| `frontend/src/api/exportUtils.ts` | Export logic |
| `frontend/src/api/graphUtils.ts` | D3 graph data |
| `frontend/src/api/profileLibraryUtils.ts` | Profile library logic |
| Any `*.test.ts` file | Tests |

---

## Inline styles situation

Many components have inline `style={{}}` props alongside CSS classes. This happened organically during development. You may:
- Move inline styles into CSS classes (preferred)
- Leave them if they're truly one-off dynamic values (e.g. `width: score%`)

Do not remove inline styles that control dynamic values like widths, colors derived from data, or D3 positions.

---

## What needs the most attention

Roughly in priority order:

1. **`styles.css`** — the biggest win. Improve spacing, typography scale, color usage, card depth/shadow, border radius consistency.

2. **Result rows** (`.result-row`, `.result-main`, `.breakdown-col`) — the core of the app. Currently functional but visually dense. Better visual hierarchy between score, technique counts, tactic bars, and the expandable sections.

3. **Sidebar** — functional but plain. Could benefit from better active state, spacing, and logo treatment.

4. **Control panels** — the left-side form panels. Field groups, radio selectors, button hierarchy.

5. **Heatmap cells** — currently use a color function, could be refined.

6. **Settings panel** — recently redesigned, fairly clean. Minor polish.

---

## What's working well — don't break it

- The **tactic bars** (`.tactic-row`, `.tactic-meter`) — the progress bar style is intentional
- The **3-column technique breakdown** (`.breakdown-col--input`, `--shared`, `--target`) — the color-coded top borders distinguish the columns
- The **chip/tag system** (`.technique-chip`, `.technique-chip.unknown-chip`) — used for technique IDs, sectors, countries, CVEs
- The **collapsible panels** (`breakdown-toggle`) — the `ChevronRight`/`ChevronDown` pattern
- The **network graph** — D3 rendered into SVG, don't touch the graph rendering code

---

## Build & preview

```bash
# Rebuild frontend image (required — no hot-reload volume mount)
docker compose build frontend && docker compose up -d frontend

# Or test build without Docker:
cd frontend && npm install && npm run build
```

The dev server runs at `http://localhost:5173`.

---

## Constraints

- No new npm packages without checking compatibility first
- Keep the single-file CSS approach (don't split into modules)
- The app must remain responsive enough to use on a 1280px wide screen
- Don't add animations that could distract from data analysis tasks
- Accessibility: keep `aria-*` attributes intact, don't remove them
