import { describe, expect, it } from "vitest";

import {
  savedAnalysisInputTypeLabel,
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
