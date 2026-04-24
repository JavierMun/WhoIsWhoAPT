import type { ActorComparisonResponse, ComparisonResult } from "./types";

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
  topN = comparison.results.length
): void {
  const payload = exportPayload(comparison, source, topN);
  const filenameBase = safeFilename(`${comparison.input_name}-${comparison.metric}`);

  if (format === "csv") {
    downloadText(`${filenameBase}.csv`, "text/csv", comparisonCsv(payload));
    return;
  }

  if (format === "navigator") {
    downloadText(
      `${filenameBase}-navigator.json`,
      "application/json",
      JSON.stringify(comparisonNavigatorLayer(payload), null, 2)
    );
    return;
  }

  downloadText(`${filenameBase}.json`, "application/json", JSON.stringify(payload, null, 2));
}

function exportPayload(comparison: ActorComparisonResponse, source: string, topN: number): ExportPayload {
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

function comparisonCsv(payload: ExportPayload): string {
  const headers = [
    "source",
    "metric",
    "generated_at",
    "input_id",
    "input_name",
    "input_type",
    "top_n",
    "rank",
    "matched_entity_id",
    "matched_entity_name",
    "matched_entity_source",
    "score",
    "technique_score",
    "software_score",
    "shared_techniques",
    "shared_software"
  ];
  const rows = payload.comparison.results.map((result, index) => [
    payload.metadata.source,
    payload.metadata.metric,
    payload.metadata.generated_at,
    payload.metadata.input_id ?? "",
    payload.metadata.input_name,
    payload.metadata.input_type,
    String(payload.metadata.top_n),
    String(index + 1),
    result.matched_entity_id,
    result.matched_entity_name,
    result.matched_entity_source,
    score(result.score),
    score(result.technique_score),
    score(result.software_score),
    result.shared_techniques.join(";"),
    result.shared_software.map((item) => item.name).join(";")
  ]);

  return [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
}

function comparisonNavigatorLayer(payload: ExportPayload): Record<string, unknown> {
  return {
    version: "4.5",
    name: `${payload.metadata.input_name} shared techniques`,
    domain: "enterprise-attack",
    description: `Shared techniques exported from WhoIsWhoAPT comparison. Source: ${payload.metadata.source}. Metric: ${payload.metadata.metric}.`,
    filters: { platforms: ["Windows", "macOS", "Linux"] },
    sorting: 0,
    layout: { layout: "side", aggregateFunction: "average", showID: false, showName: true },
    hideDisabled: false,
    metadata: [
      { name: "source", value: payload.metadata.source },
      { name: "metric", value: payload.metadata.metric },
      { name: "generated_at", value: payload.metadata.generated_at },
      { name: "input_name", value: payload.metadata.input_name },
      { name: "input_type", value: payload.metadata.input_type },
      { name: "top_n", value: String(payload.metadata.top_n) }
    ],
    techniques: navigatorTechniques(payload.comparison.results)
  };
}

function navigatorTechniques(results: ComparisonResult[]): Array<Record<string, unknown>> {
  const matchedByTechnique = new Map<string, string[]>();
  results.forEach((result) => {
    result.shared_techniques.forEach((techniqueId) => {
      matchedByTechnique.set(techniqueId, [...(matchedByTechnique.get(techniqueId) ?? []), result.matched_entity_name]);
    });
  });

  return Array.from(matchedByTechnique.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([techniqueID, matchedNames]) => ({
      techniqueID,
      score: Math.min(100, matchedNames.length),
      enabled: true,
      comment: `Shared with: ${matchedNames.sort((left, right) => left.localeCompare(right)).join(", ")}`
    }));
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

function score(value: number): string {
  return value.toFixed(6);
}

function safeFilename(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}
