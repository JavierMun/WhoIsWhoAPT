import { formatTactic } from "./ttpProfileUtils";
import type { ActorComparisonResponse, AnalysisDetail, AnalysisResponse } from "./types";

export type SavedAnalysisViewModel = {
  comparison: ActorComparisonResponse;
  topN: number;
  tacticScopeLabel: string;
  comparisonScopeLabel: string;
  tactics?: string[];
  targetIds?: string[];
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
    tactics: detail.tactics ?? undefined,
    targetIds: detail.target_ids ?? undefined
  };
}
