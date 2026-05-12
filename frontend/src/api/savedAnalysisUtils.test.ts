import { describe, expect, it } from "vitest";

import {
  nextReloadLabel,
  savedAnalysisInputTypeLabel,
  savedAnalysisDateLabel,
  savedAnalysisMetricLabel,
  savedAnalysisTargetScopeLabel,
  savedAnalysisTacticScopeLabel,
  savedAnalysisToViewModel
} from "./savedAnalysisUtils";
import type { AnalysisDetail } from "./types";

describe("saved analysis utilities", () => {
  it("formats saved analysis summary labels", () => {
    expect(savedAnalysisInputTypeLabel("actor")).toBe("Actor Profile");
    expect(savedAnalysisInputTypeLabel("custom")).toBe("Custom TTP Profile");
    expect(savedAnalysisTacticScopeLabel(null)).toBe("All tactics");
    expect(savedAnalysisTacticScopeLabel(["command-and-control", "execution"])).toBe("Command And Control, Execution");
    expect(savedAnalysisTargetScopeLabel(null)).toBe("All actor profiles");
    expect(savedAnalysisTargetScopeLabel(["actor-a"])).toBe("1 selected actor profile");
    expect(savedAnalysisTargetScopeLabel(["actor-a", "actor-b"])).toBe("2 selected actor profiles");
  });

  it("formats known metrics and keeps unknown metric names readable", () => {
    expect(savedAnalysisMetricLabel("jaccard")).toBe("Jaccard");
    expect(savedAnalysisMetricLabel("jaccard_weighted")).toBe("Weighted Jaccard");
    expect(savedAnalysisMetricLabel("tactic_weighted_jaccard")).toBe("Tactic weighted");
    expect(savedAnalysisMetricLabel("software_weighted_jaccard")).toBe("Software weighted");
    expect(savedAnalysisMetricLabel("holistic")).toBe("holistic");
    expect(savedAnalysisMetricLabel("future_metric")).toBe("future_metric");
  });

  it("formats valid dates and falls back to raw invalid timestamps", () => {
    expect(savedAnalysisDateLabel("not-a-date")).toBe("not-a-date");
    expect(savedAnalysisDateLabel("2026-04-26T12:00:00Z")).toContain("2026");
  });

  it("adapts saved analysis detail for comparison result tabs", () => {
    const viewModel = savedAnalysisToViewModel(analysisDetail());

    expect(viewModel.comparison.input_name).toBe("APT Alpha");
    expect(viewModel.topN).toBe(5);
    expect(viewModel.tacticScopeLabel).toBe("Execution");
    expect(viewModel.comparisonScopeLabel).toBe("1 selected actor profile");
    expect(viewModel.tactics).toEqual(["execution"]);
    expect(viewModel.targetIds).toEqual(["actor-b"]);
  });
});

describe("nextReloadLabel", () => {
  const base = "2026-05-07T10:00:00.000Z";

  it("returns disabled label when auto-update is off", () => {
    expect(nextReloadLabel(base, 24, false)).toBe("Auto-update disabled");
  });

  it("returns 'After first load' when no last loaded timestamp", () => {
    expect(nextReloadLabel(null, 24, true)).toBe("After first load");
  });

  it("returns 'Due now' when next reload is in the past", () => {
    const pastBase = "2026-01-01T00:00:00.000Z";
    const nowMs = new Date("2026-06-01T00:00:00.000Z").getTime();
    expect(nextReloadLabel(pastBase, 24, true, nowMs)).toBe("Due now");
  });

  it("returns hours and minutes when > 1h remaining", () => {
    const nowMs = new Date(base).getTime() + 1000; // 1 second after base
    // Frequency = 24h → next = base + 24h, diff ≈ 23h 59m
    const result = nextReloadLabel(base, 24, true, nowMs);
    expect(result).toMatch(/^in \d+h \d+m$/);
    expect(result).toContain("23h");
  });

  it("returns minutes only when < 1h remaining", () => {
    const nowMs = new Date(base).getTime() + 23.5 * 3_600_000; // 30min before next
    const result = nextReloadLabel(base, 24, true, nowMs);
    expect(result).toMatch(/^in \d+m$/);
  });
});

function analysisDetail(): AnalysisDetail {
  return {
    id: "analysis-a",
    input_type: "actor",
    input_id: "actor-a",
    input_name: "APT Alpha",
    metric: "jaccard",
    tactics: ["execution"],
    target_ids: ["actor-b"],
    top_n: 5,
    created_at: "2026-04-26T12:00:00Z",
    results: {
      input_id: "actor-a",
      input_name: "APT Alpha",
      input_type: "actor",
      metric: "jaccard",
      results: []
    }
  };
}
