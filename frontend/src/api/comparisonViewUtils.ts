import type { ActorComparisonResponse, ComparisonResult } from "./types";

export type ComparisonGraphNode = {
  id: string;
  name: string;
  score: number;
  x: number;
  y: number;
  isSource: boolean;
};

export type ComparisonGraphEdge = {
  sourceId: string;
  targetId: string;
  score: number;
};

export type ComparisonGraphData = {
  nodes: ComparisonGraphNode[];
  edges: ComparisonGraphEdge[];
  hiddenCount: number;
};

export function visibleComparisonResults(results: ComparisonResult[], limit: number): ComparisonResult[] {
  return results.slice(0, Math.max(1, limit));
}

export function comparisonHeatColor(score: number): string {
  const value = clampScore(score);
  const hue = 38 - value * 28;
  const saturation = 72 + value * 18;
  const lightness = 94 - value * 46;
  return `hsl(${hue} ${saturation}% ${lightness}%)`;
}

export function buildComparisonGraph(
  comparison: ActorComparisonResponse,
  threshold: number,
  width = 820,
  height = 480
): ComparisonGraphData {
  const centerX = width / 2;
  const centerY = height / 2;
  const visibleResults = comparison.results.filter((result) => clampScore(result.score) >= threshold);
  const radius = Math.min(width, height) * 0.34;
  const sourceNode: ComparisonGraphNode = {
    id: comparison.input_id ?? "comparison-source",
    name: comparison.input_name,
    score: 1,
    x: centerX,
    y: centerY,
    isSource: true
  };

  const targetNodes = visibleResults.map((result, index) => {
    const angle = (index / Math.max(1, visibleResults.length)) * Math.PI * 2 - Math.PI / 2;
    return {
      id: result.matched_entity_id,
      name: result.matched_entity_name,
      score: clampScore(result.score),
      x: centerX + Math.cos(angle) * radius,
      y: centerY + Math.sin(angle) * radius,
      isSource: false
    };
  });

  return {
    nodes: [sourceNode, ...targetNodes],
    edges: visibleResults.map((result) => ({
      sourceId: sourceNode.id,
      targetId: result.matched_entity_id,
      score: clampScore(result.score)
    })),
    hiddenCount: comparison.results.length - visibleResults.length
  };
}

export function clampScore(score: number): number {
  return Math.min(1, Math.max(0, score));
}
