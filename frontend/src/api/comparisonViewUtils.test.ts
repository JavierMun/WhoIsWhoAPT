import { describe, expect, it } from "vitest";

import { buildComparisonGraph, clampScore, comparisonHeatColor, visibleComparisonResults } from "./comparisonViewUtils";
import type { ActorComparisonResponse, ComparisonResult } from "./types";

describe("comparison view utilities", () => {
  it("limits visible comparison results with a minimum of one", () => {
    expect(visibleComparisonResults([result("a", 0.9), result("b", 0.5)], 1).map((item) => item.matched_entity_id)).toEqual([
      "a"
    ]);
    expect(visibleComparisonResults([result("a", 0.9), result("b", 0.5)], 0)).toHaveLength(1);
  });

  it("clamps scores into the visual range", () => {
    expect(clampScore(-1)).toBe(0);
    expect(clampScore(0.4)).toBe(0.4);
    expect(clampScore(2)).toBe(1);
  });

  it("uses stronger red-orange intensity for higher heat values", () => {
    expect(comparisonHeatColor(0)).toBe("hsl(38 72% 94%)");
    expect(comparisonHeatColor(1)).toBe("hsl(10 90% 48%)");
  });

  it("builds a thresholded source-centered graph", () => {
    const graph = buildComparisonGraph(comparison([result("alpha", 0.8), result("beta", 0.1)]), 0.5, 400, 300);

    expect(graph.nodes.map((node) => node.id)).toEqual(["source", "alpha"]);
    expect(graph.edges).toEqual([{ sourceId: "source", targetId: "alpha", score: 0.8 }]);
    expect(graph.hiddenCount).toBe(1);
  });
});

function comparison(results: ComparisonResult[]): ActorComparisonResponse {
  return {
    input_id: "source",
    input_name: "Source Actor",
    input_type: "actor",
    metric: "jaccard",
    results
  };
}

function result(id: string, score: number): ComparisonResult {
  return {
    matched_entity_id: id,
    matched_entity_name: id,
    matched_entity_source: "mitre",
    score,
    technique_score: score,
    software_score: 0,
    technique_score_contribution: score,
    software_score_contribution: 0,
    shared_techniques: [],
    unique_to_input: [],
    unique_to_matched_entity: [],
    shared_software: [],
    unique_to_input_software: [],
    unique_to_matched_entity_software: [],
    tactic_breakdown: [],
    rare_shared_techniques: [],
    explanation: null
  };
}
