import { describe, expect, it } from "vitest";

import { comparisonCsv, comparisonNavigatorLayer, exportPayload } from "./exportUtils";
import type { ActorComparisonResponse } from "./types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockComparison(overrides: Partial<ActorComparisonResponse> = {}): ActorComparisonResponse {
  return {
    input_id: "actor-a",
    input_name: "APT Alpha",
    input_type: "actor",
    metric: "jaccard",
    results: [
      {
        matched_entity_id: "actor-b",
        matched_entity_name: "APT Beta",
        matched_entity_source: "opencti",
        score: 0.5,
        technique_score: 0.5,
        software_score: 0.1,
        technique_score_contribution: 0.5,
        software_score_contribution: 0.0,
        shared_techniques: ["T1059", "T1078"],
        unique_to_input: ["T1566"],
        unique_to_matched_entity: ["T1003"],
        shared_software: [],
        unique_to_input_software: [],
        unique_to_matched_entity_software: [],
        tactic_breakdown: [],
        rare_shared_techniques: [],
        explanation: null,
        enrichment: null
      }
    ],
    ...overrides
  };
}

// ---------------------------------------------------------------------------
// CSV export
// ---------------------------------------------------------------------------

describe("comparisonCsv", () => {
  it("includes info header with source profile name and metric", () => {
    const payload = exportPayload(mockComparison(), "opencti", 10);
    const csv = comparisonCsv(payload);
    expect(csv).toContain("APT Alpha");
    expect(csv).toContain("jaccard");
  });

  it("formats similarity score as percentage string", () => {
    const payload = exportPayload(mockComparison(), "mitre", 10);
    const csv = comparisonCsv(payload);
    expect(csv).toContain("50.00%");
  });

  it("separates shared technique IDs with semicolons", () => {
    const payload = exportPayload(mockComparison(), "mitre", 10);
    const csv = comparisonCsv(payload);
    expect(csv).toContain("T1059;T1078");
  });

  it("includes correct counts", () => {
    const payload = exportPayload(mockComparison(), "mitre", 10);
    const csv = comparisonCsv(payload);
    expect(csv).toContain('"2"');   // shared_ttp_count
    expect(csv).toContain('"1"');   // input_only_count and target_only_count
  });

  it("includes unique technique IDs for input and target", () => {
    const payload = exportPayload(mockComparison(), "mitre", 10);
    const csv = comparisonCsv(payload);
    expect(csv).toContain("T1566");   // input-only
    expect(csv).toContain("T1003");   // target-only
  });

  it("includes rank starting at 1", () => {
    const payload = exportPayload(mockComparison(), "mitre", 10);
    const csv = comparisonCsv(payload);
    expect(csv).toContain('"1"');   // rank = 1
  });
});

// ---------------------------------------------------------------------------
// Navigator comparison export
// ---------------------------------------------------------------------------

describe("comparisonNavigatorLayer", () => {
  it("includes gradient field so scores map to visible colors", () => {
    const payload = exportPayload(mockComparison(), "mitre", 10);
    const layer = comparisonNavigatorLayer(payload);
    expect(layer).toHaveProperty("gradient");
    const g = layer.gradient as { colors: string[]; minValue: number };
    expect(g.colors).toHaveLength(2);
    expect(g.minValue).toBe(1);
  });

  it("includes shared techniques as scored entries (no fixed color)", () => {
    const payload = exportPayload(mockComparison(), "mitre", 10);
    const layer = comparisonNavigatorLayer(payload);
    const techs = layer.techniques as Array<{ techniqueID: string; score?: number; color?: string }>;
    const shared = techs.find((t) => t.techniqueID === "T1059");
    expect(shared).toBeDefined();
    expect(shared?.score).toBe(1);
    expect(shared?.color).toBeUndefined();
  });

  it("colors source-only techniques blue", () => {
    const payload = exportPayload(mockComparison(), "mitre", 10);
    const layer = comparisonNavigatorLayer(payload);
    const techs = layer.techniques as Array<{ techniqueID: string; color?: string }>;
    const sourceOnly = techs.find((t) => t.techniqueID === "T1566");
    expect(sourceOnly).toBeDefined();
    expect(sourceOnly?.color).toBe("#4a9eff");
  });

  it("does not include target-only techniques", () => {
    const payload = exportPayload(mockComparison(), "mitre", 10);
    const layer = comparisonNavigatorLayer(payload);
    const techs = layer.techniques as Array<{ techniqueID: string }>;
    expect(techs.find((t) => t.techniqueID === "T1003")).toBeUndefined();
  });

  it("includes legend items for both color bands", () => {
    const payload = exportPayload(mockComparison(), "mitre", 10);
    const layer = comparisonNavigatorLayer(payload);
    const legends = layer.legendItems as Array<{ color: string }>;
    expect(legends.length).toBeGreaterThanOrEqual(2);
    expect(legends.some((l) => l.color === "#4a9eff")).toBe(true);
  });

  it("technique comment lists which actors share it", () => {
    const payload = exportPayload(mockComparison(), "mitre", 10);
    const layer = comparisonNavigatorLayer(payload);
    const techs = layer.techniques as Array<{ techniqueID: string; comment: string }>;
    const shared = techs.find((t) => t.techniqueID === "T1059");
    expect(shared?.comment).toContain("APT Beta");
  });

  it("uses 'enterprise-attack' domain", () => {
    const payload = exportPayload(mockComparison(), "mitre", 10);
    const layer = comparisonNavigatorLayer(payload);
    expect(layer.domain).toBe("enterprise-attack");
  });

  it("layer name includes source profile name", () => {
    const payload = exportPayload(mockComparison(), "mitre", 10);
    const layer = comparisonNavigatorLayer(payload);
    expect((layer.name as string)).toContain("APT Alpha");
  });
});

// ---------------------------------------------------------------------------
// Multiple matched actors — score increments
// ---------------------------------------------------------------------------

describe("Navigator scoring with multiple actors", () => {
  it("shared-by-2-actors technique gets score 2", () => {
    const comparison = mockComparison({
      results: [
        {
          matched_entity_id: "b", matched_entity_name: "Actor B",
          matched_entity_source: "opencti", score: 0.5,
          technique_score: 0.5, software_score: 0, technique_score_contribution: 0.5, software_score_contribution: 0,
          shared_techniques: ["T1059"], unique_to_input: [], unique_to_matched_entity: [],
          shared_software: [], unique_to_input_software: [], unique_to_matched_entity_software: [],
          tactic_breakdown: [], rare_shared_techniques: [], explanation: null, enrichment: null
        },
        {
          matched_entity_id: "c", matched_entity_name: "Actor C",
          matched_entity_source: "opencti", score: 0.4,
          technique_score: 0.4, software_score: 0, technique_score_contribution: 0.4, software_score_contribution: 0,
          shared_techniques: ["T1059"], unique_to_input: [], unique_to_matched_entity: [],
          shared_software: [], unique_to_input_software: [], unique_to_matched_entity_software: [],
          tactic_breakdown: [], rare_shared_techniques: [], explanation: null, enrichment: null
        }
      ]
    });
    const payload = exportPayload(comparison, "mitre", 10);
    const layer = comparisonNavigatorLayer(payload);
    const techs = layer.techniques as Array<{ techniqueID: string; score: number }>;
    const t = techs.find((e) => e.techniqueID === "T1059");
    expect(t?.score).toBe(2);
  });
});
