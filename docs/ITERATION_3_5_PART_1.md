# Iteration 3.5 Part 1 - Modular Frontend Navigation

## Implemented

The frontend now uses a modular application shell instead of rendering every analysis panel on one long page.

Sidebar modules:

- Compare
- TTP Profiles
- Visual Analysis
- Settings

Only the selected module is rendered. Existing backend endpoints, scoring logic, analytics behavior, and panel internals were left unchanged.

## Module Structure

### Compare

Contains the existing actor/profile comparison workflow:

- `ActorComparisonPanel`

### TTP Profiles

Contains workflows for creating, importing, saving, inspecting, and comparing custom or incident-derived TTP profiles:

- `CustomTTPSetPanel`
- `IncidentAnalysisPanel`

The incident panel is kept here temporarily as an incident/profile workflow because it operates on observed technique sets and compares them to actor profiles.

### Visual Analysis

Contains global matrix and graph exploration:

- `ActorMatrixHeatmapPanel`
- `ActorNetworkGraphPanel`

### Settings

Contains current backend/source status:

- backend health status
- backend environment
- active source placeholder showing the MITRE dataset

## Files

- `frontend/src/App.tsx` owns the active module state and renders the selected module.
- `frontend/src/components/Layout.tsx` provides the application shell.
- `frontend/src/components/Sidebar.tsx` provides module navigation.
- `frontend/src/components/SettingsPanel.tsx` provides the current settings/status placeholder.
- `frontend/src/styles.css` adds styling for module navigation, stacked module content, and settings status.

## Manual Test

Start the stack:

```powershell
docker compose up -d --build backend frontend
```

Open:

```text
http://localhost:5173
```

Test each module:

1. Compare
   - Select an actor.
   - Choose a metric.
   - Run comparison.
   - Confirm ranked results and export buttons still behave as before.
2. TTP Profiles
   - Create or import techniques in Custom TTP Sets.
   - Save and compare an inline or saved custom set.
   - Use Incident Analysis by pasting technique IDs or importing Navigator JSON.
   - Confirm JSON, CSV, and Navigator exports still work for results.
3. Visual Analysis
   - Compute or retrieve a heatmap matrix.
   - Filter actors and adjust the visible actor limit.
   - Load the actor relationship graph.
   - Adjust threshold and node limit.
   - Export graph JSON.
4. Settings
   - Confirm backend status and environment render.
   - Confirm errors are shown if the backend health check fails.

## Validation

Frontend validation:

```powershell
docker compose run --rm frontend npm run build
docker compose run --rm frontend npm run lint
```

Backend tests are not changed by this part because no backend code, endpoints, or analytics logic were modified.
