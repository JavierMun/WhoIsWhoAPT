import type { ActorComparisonResponse, ComparisonResult } from "./types";
import { techniqueLabel, type TechniqueLookup } from "./ttpProfileUtils";

type ExportMetadata = {
  source: string;
  metric: string;
  generated_at: string;
  input_id: string | null;
  input_name: string;
  input_type: string;
  top_n: number;
};

type ExportPayload = {
  metadata: ExportMetadata;
  comparison: ActorComparisonResponse;
};

export type ExportFormat = "json" | "csv" | "navigator";

export function downloadComparisonExport(
  comparison: ActorComparisonResponse,
  format: ExportFormat,
  source = "mitre",
  topN = comparison.results.length,
  techniqueLookup?: TechniqueLookup
): void {
  // techniqueLookup used for tactic field in Navigator and names in CSV
  const payload = exportPayload(comparison, source, topN);
  const filenameBase = safeFilename(`${comparison.input_name}-${comparison.metric}`);

  if (format === "csv") {
    downloadText(`${filenameBase}.csv`, "text/csv", comparisonCsv(payload, techniqueLookup));
    return;
  }

  if (format === "navigator") {
    downloadText(
      `${filenameBase}-navigator.json`,
      "application/json",
      JSON.stringify(comparisonNavigatorLayer(payload, techniqueLookup), null, 2)
    );
    return;
  }

  downloadText(`${filenameBase}.json`, "application/json", JSON.stringify(payload, null, 2));
}

export function exportPayload(comparison: ActorComparisonResponse, source: string, topN: number): ExportPayload {
  return {
    metadata: {
      source,
      metric: comparison.metric,
      generated_at: new Date().toISOString(),
      input_id: comparison.input_id,
      input_name: comparison.input_name,
      input_type: comparison.input_type,
      top_n: topN
    },
    comparison
  };
}

export function comparisonCsv(payload: ExportPayload, techniqueLookup?: TechniqueLookup): string {
  // Header row: info about the comparison
  const infoRows = [
    ["WhoIsWhoAPT Comparison Export"],
    ["Source profile", payload.metadata.input_name],
    ["Metric", payload.metadata.metric],
    ["Generated", payload.metadata.generated_at],
    ["Source", payload.metadata.source],
    [],
  ];

  // Result rows
  const resultHeaders = [
    "rank",
    "actor_name",
    "actor_source",
    "similarity_pct",
    "technique_score_pct",
    "shared_ttp_count",
    "input_only_count",
    "target_only_count",
    "shared_software_count",
    "shared_technique_ids",
    "shared_technique_names",
    "input_only_ids",
    "target_only_ids",
    "shared_software"
  ];

  const resultRows = payload.comparison.results.map((result, index) => [
    String(index + 1),
    result.matched_entity_name,
    result.matched_entity_source,
    pct(result.score),
    pct(result.technique_score),
    String(result.shared_techniques.length),
    String(result.unique_to_input.length),
    String(result.unique_to_matched_entity.length),
    String(result.shared_software.length),
    result.shared_techniques.join(";"),
    result.shared_techniques.map((id) => (techniqueLookup?.get(id)?.name ?? id)).join(";"),
    result.unique_to_input.join(";"),
    result.unique_to_matched_entity.join(";"),
    result.shared_software.map((item) => item.name).join(";")
  ]);

  const infoSection = infoRows.map((row) => row.map(csvCell).join(",")).join("\n");
  const resultsSection = [resultHeaders, ...resultRows].map((row) => row.map(csvCell).join(",")).join("\n");
  return `${infoSection}\n${resultsSection}`;
}

function formatTechnique(techniqueId: string, techniqueLookup?: TechniqueLookup): string {
  return techniqueLookup ? techniqueLabel(techniqueId, techniqueLookup) : techniqueId;
}

export function comparisonNavigatorLayer(payload: ExportPayload, techniqueLookup?: TechniqueLookup): Record<string, unknown> {
  const techniques = navigatorTechniques(payload.comparison.results, techniqueLookup);
  const maxScore = Math.max(1, ...techniques.map((t) => t.score as number));

  return {
    version: "4.5",
    name: `${payload.metadata.input_name} — shared TTPs`,
    domain: "enterprise-attack",
    description: `Techniques shared between ${payload.metadata.input_name} and top-${payload.metadata.top_n} matched actors. Exported from WhoIsWhoAPT · metric: ${payload.metadata.metric}.`,
    filters: { platforms: ["Windows", "macOS", "Linux"] },
    sorting: 3,  // sort by score descending
    layout: { layout: "side", aggregateFunction: "sum", showID: true, showName: true, showAggregateScores: true },
    hideDisabled: false,
    // Gradient: light orange (shared by 1 actor) → dark orange (shared by many)
    gradient: {
      colors: ["#ffd9b3", "#ff6b00"],
      minValue: 1,
      maxValue: maxScore
    },
    legendItems: [
      { label: "Shared by 1 actor", color: "#ffd9b3" },
      { label: `Shared by ${maxScore} actors`, color: "#ff6b00" },
      { label: "Source-only (not in any matched actor)", color: "#4a9eff" }
    ],
    metadata: [
      { name: "source_profile", value: payload.metadata.input_name },
      { name: "metric", value: payload.metadata.metric },
      { name: "generated_at", value: payload.metadata.generated_at },
      { name: "data_source", value: payload.metadata.source }
    ],
    techniques
  };
}

function navigatorTechniques(results: ComparisonResult[], techniqueLookup?: TechniqueLookup): Array<Record<string, unknown>> {
  // Shared: technique appears in at least one result's shared_techniques
  const matchedByTechnique = new Map<string, string[]>();
  results.forEach((result) => {
    result.shared_techniques.forEach((id) => {
      matchedByTechnique.set(id, [...(matchedByTechnique.get(id) ?? []), result.matched_entity_name]);
    });
  });

  // Source-only: in unique_to_input for at least one result but NEVER in shared_techniques
  const sharedAll = new Set(matchedByTechnique.keys());
  const sourceOnlyIds = new Set(
    results.flatMap((r) => r.unique_to_input).filter((id) => !sharedAll.has(id))
  );

  function tacticFor(techniqueID: string): string | undefined {
    const t = techniqueLookup?.get(techniqueID);
    if (!t?.tactic) return undefined;
    // Use the first individual tactic (split by comma)
    return t.tactic.split(",")[0].trim().toLowerCase().replace(/\s+/g, "-") || undefined;
  }

  const sharedEntries = Array.from(matchedByTechnique.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([techniqueID, matchedNames]) => {
      const sorted = matchedNames.sort((a, b) => a.localeCompare(b));
      const tactic = tacticFor(techniqueID);
      return {
        techniqueID,
        ...(tactic ? { tactic } : {}),
        score: sorted.length,
        enabled: true,
        comment: `Shared with (${sorted.length}): ${sorted.join(", ")}`
      };
    });

  const sourceOnlyEntries = Array.from(sourceOnlyIds)
    .sort((a, b) => a.localeCompare(b))
    .map((techniqueID) => {
      const tactic = tacticFor(techniqueID);
      return {
        techniqueID,
        ...(tactic ? { tactic } : {}),
        color: "#4a9eff",
        enabled: true,
        comment: "Source-only — not found in any of the matched actors"
      };
    });

  return [...sharedEntries, ...sourceOnlyEntries];
}

function pct(value: number): string {
  return `${(value * 100).toFixed(2)}%`;
}

function downloadText(filename: string, mediaType: string, content: string): void {
  const blob = new Blob([content], { type: mediaType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function csvCell(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function safeFilename(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}
