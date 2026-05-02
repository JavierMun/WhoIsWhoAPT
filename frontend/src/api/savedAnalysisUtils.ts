import { formatTactic } from "./ttpProfileUtils";
import type { ActorComparisonResponse, AnalysisDetail, AnalysisResponse } from "./types";

export type SavedAnalysisViewModel = {
  comparison: ActorComparisonResponse;
  topN: number;
  tacticScopeLabel: string;
  comparisonScopeLabel: string;
  enrichmentFilterLabel: string | null;
  tactics?: string[];
  targetIds?: string[];
  filterSectors?: string[];
  filterCountries?: string[];
};

export function savedAnalysisInputTypeLabel(inputType: AnalysisResponse["input_type"]): string {
  return inputType === "actor" ? "Actor Profile" : "Custom TTP Profile";
}

export function savedAnalysisMetricLabel(metric: string): string {
  if (metric === "jaccard_weighted") {
    return "Weighted Jaccard";
  }
  if (metric === "tactic_weighted_jaccard") {
    return "Tactic weighted";
  }
  if (metric === "software_weighted_jaccard") {
    return "Software weighted";
  }
  if (metric === "jaccard") {
    return "Jaccard";
  }
  return metric;
}

export function savedAnalysisTacticScopeLabel(tactics: string[] | null | undefined): string {
  if (!tactics || tactics.length === 0) {
    return "All tactics";
  }
  return tactics.map((tactic) => formatTactic(tactic)).join(", ");
}

export function savedAnalysisTargetScopeLabel(targetIds: string[] | null | undefined): string {
  if (!targetIds || targetIds.length === 0) {
    return "All actor profiles";
  }
  return `${targetIds.length} selected actor ${targetIds.length === 1 ? "profile" : "profiles"}`;
}

export function savedAnalysisEnrichmentFilterLabel(
  filterSectors: string[] | null | undefined,
  filterCountries: string[] | null | undefined
): string | null {
  const parts: string[] = [];
  if (filterSectors && filterSectors.length > 0) {
    parts.push(`Sectors: ${filterSectors.join(", ")}`);
  }
  if (filterCountries && filterCountries.length > 0) {
    parts.push(`Countries: ${filterCountries.join(", ")}`);
  }
  return parts.length > 0 ? parts.join(" · ") : null;
}

export function savedAnalysisDateLabel(createdAt: string): string {
  const date = new Date(createdAt);
  if (Number.isNaN(date.getTime())) {
    return createdAt;
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(date);
}

export function savedAnalysisToViewModel(detail: AnalysisDetail): SavedAnalysisViewModel {
  return {
    comparison: detail.results,
    topN: detail.top_n,
    tacticScopeLabel: savedAnalysisTacticScopeLabel(detail.tactics),
    comparisonScopeLabel: savedAnalysisTargetScopeLabel(detail.target_ids),
    enrichmentFilterLabel: savedAnalysisEnrichmentFilterLabel(detail.filter_sectors, detail.filter_countries),
    tactics: detail.tactics ?? undefined,
    targetIds: detail.target_ids ?? undefined,
    filterSectors: detail.filter_sectors ?? undefined,
    filterCountries: detail.filter_countries ?? undefined
  };
}
