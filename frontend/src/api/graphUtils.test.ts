import { describe, expect, it } from "vitest";

import { buildGraphData, MAX_GRAPH_EDGES } from "./graphUtils";
import type { ClusterResponse, MatrixResponse } from "./types";

describe("buildGraphData", () => {
  it("returns no edges when the threshold is above all similarities", () => {
    const graph = buildGraphData(matrix(3, 0.2), clusters(3), 0.9, 3);

    expect(graph.nodes).toHaveLength(3);
    expect(graph.links).toHaveLength(0);
    expect(graph.totalEdgeCount).toBe(0);
  });

  it("filters edges above the selected threshold", () => {
    const graph = buildGraphData(matrix(3, 0.2, [[0, 1, 0.8]]), clusters(3), 0.5, 3);

    expect(graph.totalEdgeCount).toBe(1);
    expect(graph.links).toEqual([{ source: "actor-0", target: "actor-1", similarity: 0.8 }]);
  });

  it("caps very dense graphs to the strongest edges", () => {
    const graph = buildGraphData(matrix(40, 0.7), clusters(40), 0.1, 40);

    expect(graph.totalEdgeCount).toBeGreaterThan(MAX_GRAPH_EDGES);
    expect(graph.links).toHaveLength(MAX_GRAPH_EDGES);
    expect(graph.omittedEdgeCount).toBe(graph.totalEdgeCount - MAX_GRAPH_EDGES);
  });
});

function matrix(size: number, defaultSimilarity: number, overrides: Array<[number, number, number]> = []): MatrixResponse {
  const values = Array.from({ length: size }, (_, rowIndex) =>
    Array.from({ length: size }, (_, columnIndex) => (rowIndex === columnIndex ? 1 : defaultSimilarity))
  );
  overrides.forEach(([rowIndex, columnIndex, similarity]) => {
    values[rowIndex][columnIndex] = similarity;
    values[columnIndex][rowIndex] = similarity;
  });

  return {
    metadata: {
      source: "mitre",
      metric: "jaccard",
      generated_at: "2026-04-24T10:00:00Z",
      actor_count: size
    },
    actors: Array.from({ length: size }, (_, index) => ({
      id: `actor-${index}`,
      name: `Actor ${index}`,
      source: "mitre"
    })),
    matrix: values
  };
}

function clusters(size: number): ClusterResponse {
  return {
    source: "mitre",
    metric: "jaccard",
    generated_at: "2026-04-24T10:00:00Z",
    actor_count: size,
    cluster_count: size,
    min_similarity: 0.15,
    labels: Array.from({ length: size }, (_, index) => ({
      actor_id: `actor-${index}`,
      actor_name: `Actor ${index}`,
      source: "mitre",
      cluster_id: index + 1
    }))
  };
}
