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
  const v = clampScore(score);
  if (v === 0) return "#0e1318";
  // Dark theme: near-black → dark teal → amber → bright orange
  const stops: [number, [number, number, number]][] = [
    [0,    [14,  19,  24]],   // bg-1 dark
    [0.1,  [15,  50,  60]],   // very dark teal
    [0.3,  [10,  100, 90]],   // dark teal/green
    [0.55, [120, 80,  40]],   // amber/brown
    [0.75, [180, 90,  50]],   // orange
    [1.0,  [220, 100, 60]],   // bright orange
  ];
  for (let i = 1; i < stops.length; i++) {
    const [t0, c0] = stops[i - 1];
    const [t1, c1] = stops[i];
    if (v <= t1) {
      const t = (v - t0) / (t1 - t0);
      const r = Math.round(c0[0] + (c1[0] - c0[0]) * t);
      const g = Math.round(c0[1] + (c1[1] - c0[1]) * t);
      const b = Math.round(c0[2] + (c1[2] - c0[2]) * t);
      return `rgb(${r},${g},${b})`;
    }
  }
  return "rgb(220,100,60)";
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
