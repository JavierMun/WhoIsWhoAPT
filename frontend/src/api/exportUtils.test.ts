import { describe, expect, it, vi } from "vitest";

// Mock URL.createObjectURL so download tests don't fail in JSDOM
vi.stubGlobal("URL", { createObjectURL: () => "blob:mock", revokeObjectURL: () => {} });

import { downloadComparisonExport } from "./exportUtils";
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

function captureDownload(): { filename: string; content: string } | null {
  let captured: { filename: string; content: string } | null = null;
  const origCreateElement = document.createElement.bind(document);
  vi.spyOn(document, "createElement").mockImplementation((tag: string) => {
    const el = origCreateElement(tag);
    if (tag === "a") {
      Object.defineProperty(el, "download", { set(v: string) { captured = { filename: v, content: "" }; }, get() { return ""; } });
      vi.spyOn(el, "click").mockImplementation(() => {});
    }
    return el;
  });
  return captured;
}

// ---------------------------------------------------------------------------
// CSV export
// ---------------------------------------------------------------------------

describe("CSV export", () => {
  it("includes info header and result row", () => {
    const comparison = mockComparison();
    let blobContent = "";
    vi.spyOn(globalThis, "Blob").mockImplementationOnce((parts) => {
      blobContent = parts?.join("") ?? "";
      return { size: 0, type: "" } as Blob;
    });

    downloadComparisonExport(comparison, "csv");

    expect(blobContent).toContain("APT Alpha");
    expect(blobContent).toContain("jaccard");
    expect(blobContent).toContain("APT Beta");
  });

  it("formats similarity as percentage", () => {
    const comparison = mockComparison();
    let blobContent = "";
    vi.spyOn(globalThis, "Blob").mockImplementationOnce((parts) => {
      blobContent = parts?.join("") ?? "";
      return { size: 0, type: "" } as Blob;
    });

    downloadComparisonExport(comparison, "csv");

    expect(blobContent).toContain("50.00%");
  });

  it("separates shared technique IDs with semicolons", () => {
    const comparison = mockComparison();
    let blobContent = "";
    vi.spyOn(globalThis, "Blob").mockImplementationOnce((parts) => {
      blobContent = parts?.join("") ?? "";
      return { size: 0, type: "" } as Blob;
    });

    downloadComparisonExport(comparison, "csv");

    expect(blobContent).toContain("T1059;T1078");
  });

  it("includes unique technique counts", () => {
    const comparison = mockComparison();
    let blobContent = "";
    vi.spyOn(globalThis, "Blob").mockImplementationOnce((parts) => {
      blobContent = parts?.join("") ?? "";
      return { size: 0, type: "" } as Blob;
    });

    downloadComparisonExport(comparison, "csv");

    // shared_ttp_count = 2, input_only_count = 1, target_only_count = 1
    expect(blobContent).toContain('"2"');
    expect(blobContent).toContain('"1"');
  });
});

// ---------------------------------------------------------------------------
// Navigator export — comparison
// ---------------------------------------------------------------------------

describe("Navigator comparison export", () => {
  it("includes gradient field for score-based coloring", () => {
    const comparison = mockComparison();
    let blobContent = "";
    vi.spyOn(globalThis, "Blob").mockImplementationOnce((parts) => {
      blobContent = parts?.join("") ?? "";
      return { size: 0, type: "" } as Blob;
    });

    downloadComparisonExport(comparison, "navigator");

    const layer = JSON.parse(blobContent);
    expect(layer).toHaveProperty("gradient");
    expect(layer.gradient.colors).toHaveLength(2);
    expect(layer.gradient.minValue).toBe(1);
  });

  it("colors shared techniques with score", () => {
    const comparison = mockComparison();
    let blobContent = "";
    vi.spyOn(globalThis, "Blob").mockImplementationOnce((parts) => {
      blobContent = parts?.join("") ?? "";
      return { size: 0, type: "" } as Blob;
    });

    downloadComparisonExport(comparison, "navigator");

    const layer = JSON.parse(blobContent);
    const sharedT = layer.techniques.find((t: { techniqueID: string }) => t.techniqueID === "T1059");
    expect(sharedT).toBeDefined();
    expect(sharedT.score).toBe(1);  // shared with 1 actor
    expect(sharedT.color).toBeUndefined();  // uses gradient, no fixed color
  });

  it("colors source-only techniques in blue", () => {
    const comparison = mockComparison();
    let blobContent = "";
    vi.spyOn(globalThis, "Blob").mockImplementationOnce((parts) => {
      blobContent = parts?.join("") ?? "";
      return { size: 0, type: "" } as Blob;
    });

    downloadComparisonExport(comparison, "navigator");

    const layer = JSON.parse(blobContent);
    const sourceOnly = layer.techniques.find((t: { techniqueID: string }) => t.techniqueID === "T1566");
    expect(sourceOnly).toBeDefined();
    expect(sourceOnly.color).toBe("#4a9eff");
  });

  it("does not include target-only techniques", () => {
    const comparison = mockComparison();
    let blobContent = "";
    vi.spyOn(globalThis, "Blob").mockImplementationOnce((parts) => {
      blobContent = parts?.join("") ?? "";
      return { size: 0, type: "" } as Blob;
    });

    downloadComparisonExport(comparison, "navigator");

    const layer = JSON.parse(blobContent);
    const targetOnly = layer.techniques.find((t: { techniqueID: string }) => t.techniqueID === "T1003");
    expect(targetOnly).toBeUndefined();
  });

  it("includes legend items", () => {
    const comparison = mockComparison();
    let blobContent = "";
    vi.spyOn(globalThis, "Blob").mockImplementationOnce((parts) => {
      blobContent = parts?.join("") ?? "";
      return { size: 0, type: "" } as Blob;
    });

    downloadComparisonExport(comparison, "navigator");

    const layer = JSON.parse(blobContent);
    expect(layer.legendItems.length).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// JSON export
// ---------------------------------------------------------------------------

describe("JSON export", () => {
  it("includes full comparison payload", () => {
    const comparison = mockComparison();
    let blobContent = "";
    vi.spyOn(globalThis, "Blob").mockImplementationOnce((parts) => {
      blobContent = parts?.join("") ?? "";
      return { size: 0, type: "" } as Blob;
    });

    downloadComparisonExport(comparison, "json");

    const payload = JSON.parse(blobContent);
    expect(payload.metadata.input_name).toBe("APT Alpha");
    expect(payload.comparison.results).toHaveLength(1);
  });
});
