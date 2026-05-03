import type { ClusterResponse, MatrixResponse } from "./types";

export const MAX_GRAPH_EDGES = 600;

export type GraphNode = {
  id: string;
  name: string;
  clusterId: number;
  averageSimilarity: number;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  fx?: number | null;
  fy?: number | null;
  index?: number;
};

export type GraphLink = {
  source: string | GraphNode;
  target: string | GraphNode;
  similarity: number;
  index?: number;
};

export type GraphData = {
  nodes: GraphNode[];
  links: GraphLink[];
  totalEdgeCount: number;
  omittedEdgeCount: number;
};

export function buildGraphData(
  matrix: MatrixResponse | null,
  clusters: ClusterResponse | null,
  threshold: number,
  nodeLimit: number
): GraphData {
  if (!matrix || !clusters) {
    return { nodes: [], links: [], totalEdgeCount: 0, omittedEdgeCount: 0 };
  }

  const safeThreshold = clampScore(threshold);
  const safeNodeLimit = Math.max(1, nodeLimit);
  const clusterByActorId = new Map(clusters.labels.map((label) => [label.actor_id, label.cluster_id]));
  const actorScores = matrix.actors.map((actor, index) => {
    const row = matrix.matrix[index] ?? [];
    const comparableValues = row.filter((_, columnIndex) => columnIndex !== index);
    const averageSimilarity =
      comparableValues.length > 0
        ? comparableValues.reduce((total, value) => total + clampScore(value), 0) / comparableValues.length
        : 0;
    return { actor, index, averageSimilarity };
  });
  const visibleActors = actorScores
    .sort((left, right) => right.averageSimilarity - left.averageSimilarity || left.actor.name.localeCompare(right.actor.name))
    .slice(0, safeNodeLimit);
  const visibleIndexes = new Set(visibleActors.map((item) => item.index));
  const nodes = visibleActors.map(({ actor, averageSimilarity }) => ({
    id: actor.id,
    name: actor.name,
    clusterId: clusterByActorId.get(actor.id) ?? 0,
    averageSimilarity
  }));
  const allLinks: GraphLink[] = [];

  for (const sourceIndex of visibleIndexes) {
    for (const targetIndex of visibleIndexes) {
      if (sourceIndex >= targetIndex) {
        continue;
      }
      const similarity = clampScore(matrix.matrix[sourceIndex]?.[targetIndex] ?? 0);
      if (similarity > safeThreshold) {
        allLinks.push({
          source: matrix.actors[sourceIndex].id,
          target: matrix.actors[targetIndex].id,
          similarity
        });
      }
    }
  }

  allLinks.sort((left, right) => right.similarity - left.similarity || linkKey(left).localeCompare(linkKey(right)));
  const links = allLinks.slice(0, MAX_GRAPH_EDGES);

  return {
    nodes,
    links,
    totalEdgeCount: allLinks.length,
    omittedEdgeCount: Math.max(0, allLinks.length - links.length)
  };
}

function linkKey(link: GraphLink): string {
  return `${endpointId(link.source)}-${endpointId(link.target)}`;
}

function endpointId(endpoint: string | GraphNode): string {
  return typeof endpoint === "string" ? endpoint : endpoint.id;
}

function clampScore(score: number): number {
  return Math.min(1, Math.max(0, score));
}
