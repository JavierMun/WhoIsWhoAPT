import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  type SimulationLinkDatum,
  type SimulationNodeDatum
} from "d3-force";
import { AlertCircle, Loader2, Network, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { computeMatrix, getClusters, getMatrixResult } from "../api/client";
import type { ClusterResponse, MatrixResponse, SimilarityMetric } from "../api/types";

const DEFAULT_THRESHOLD = 0.15;
const DEFAULT_NODE_LIMIT = 60;
const MAX_NODE_LIMIT = 100;
const GRAPH_WIDTH = 920;
const GRAPH_HEIGHT = 560;
const CLUSTER_COLORS = ["#136f63", "#7c3aed", "#c2410c", "#2563eb", "#a21caf", "#0f766e", "#b45309", "#be123c"];

type GraphNode = SimulationNodeDatum & {
  id: string;
  name: string;
  clusterId: number;
  averageSimilarity: number;
};

type GraphLink = SimulationLinkDatum<GraphNode> & {
  source: string | GraphNode;
  target: string | GraphNode;
  similarity: number;
};

export function ActorNetworkGraphPanel() {
  const [metric, setMetric] = useState<SimilarityMetric>("jaccard");
  const [threshold, setThreshold] = useState(DEFAULT_THRESHOLD);
  const [nodeLimit, setNodeLimit] = useState(DEFAULT_NODE_LIMIT);
  const [matrix, setMatrix] = useState<MatrixResponse | null>(null);
  const [clusters, setClusters] = useState<ClusterResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleLoadGraph() {
    setLoading(true);
    setError(null);

    try {
      let activeMatrix: MatrixResponse;
      try {
        activeMatrix = await getMatrixResult();
      } catch {
        activeMatrix = await computeMatrix(metric);
      }

      if (activeMatrix.metadata.metric !== metric) {
        activeMatrix = await computeMatrix(metric);
      }

      setMatrix(activeMatrix);
      setClusters(await getClusters(threshold));
    } catch (apiError) {
      setError(apiError instanceof Error ? apiError.message : "Unable to load graph data");
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="comparison-workspace network-workspace" aria-labelledby="network-title">
      <div className="workspace-header">
        <div>
          <p className="eyebrow">Cluster Network</p>
          <h1 id="network-title">Actor relationship graph</h1>
        </div>
        <div className="source-pill">
          <Network size={16} aria-hidden="true" />
          <span>{clusters ? `${clusters.cluster_count} clusters` : "Network"}</span>
        </div>
      </div>

      <div className="network-layout">
        <form
          className="control-panel network-controls"
          onSubmit={(event) => {
            event.preventDefault();
            void handleLoadGraph();
          }}
        >
          <label className="field-group" htmlFor="network-metric-select">
            <span>Metric</span>
            <select
              id="network-metric-select"
              value={metric}
              onChange={(event) => {
                setMetric(event.target.value as SimilarityMetric);
              }}
            >
              <option value="jaccard">Jaccard</option>
              <option value="jaccard_weighted">Weighted Jaccard</option>
              <option value="tactic_weighted_jaccard">Tactic weighted</option>
              <option value="software_weighted_jaccard">Software weighted</option>
            </select>
          </label>

          <label className="field-group" htmlFor="network-threshold">
            <span>Similarity threshold</span>
            <input
              id="network-threshold"
              type="range"
              min={0}
              max={1}
              step={0.01}
              value={threshold}
              onChange={(event) => {
                setThreshold(Number(event.target.value));
              }}
            />
            <span className="field-hint">{formatScore(threshold)} and higher</span>
          </label>

          <label className="field-group" htmlFor="network-node-limit">
            <span>Node limit</span>
            <input
              id="network-node-limit"
              type="number"
              min={5}
              max={MAX_NODE_LIMIT}
              value={nodeLimit}
              onChange={(event) => {
                const nextValue = Number(event.target.value);
                setNodeLimit(
                  Number.isFinite(nextValue) ? Math.min(MAX_NODE_LIMIT, Math.max(5, nextValue)) : DEFAULT_NODE_LIMIT
                );
              }}
            />
          </label>

          <button className="primary-action" type="submit" disabled={loading}>
            {loading ? <Loader2 className="spin" size={18} aria-hidden="true" /> : <Network size={18} aria-hidden="true" />}
            <span>{loading ? "Loading graph" : "Load graph"}</span>
          </button>

          <button className="secondary-action" type="button" disabled={loading} onClick={() => void handleLoadGraph()}>
            <RefreshCw size={18} aria-hidden="true" />
            <span>Refresh</span>
          </button>

          <div className="graph-legend" aria-label="Graph legend">
            <div className="mini-header">
              <strong>Legend</strong>
              <span>Cluster colors</span>
            </div>
            <div className="cluster-swatches">
              {CLUSTER_COLORS.slice(0, 6).map((color, index) => (
                <span key={color} style={{ backgroundColor: color }} title={`Cluster ${index + 1}`} />
              ))}
            </div>
            <p>Edges appear when similarity is above the selected threshold.</p>
          </div>

          {error ? <StatusMessage message={error} /> : null}
        </form>

        <NetworkPanel matrix={matrix} clusters={clusters} threshold={threshold} nodeLimit={nodeLimit} loading={loading} />
      </div>
    </section>
  );
}

function NetworkPanel({
  matrix,
  clusters,
  threshold,
  nodeLimit,
  loading
}: {
  matrix: MatrixResponse | null;
  clusters: ClusterResponse | null;
  threshold: number;
  nodeLimit: number;
  loading: boolean;
}) {
  const graph = useGraphData(matrix, clusters, threshold, nodeLimit);

  if (loading) {
    return (
      <section className="results-panel network-panel" aria-live="polite">
        <div className="empty-state">
          <Loader2 className="spin" size={22} aria-hidden="true" />
          <p>Building network</p>
        </div>
      </section>
    );
  }

  if (!matrix || !clusters) {
    return (
      <section className="results-panel network-panel">
        <div className="empty-state">
          <Network size={24} aria-hidden="true" />
          <p>Load graph data from the latest matrix.</p>
        </div>
      </section>
    );
  }

  if (graph.nodes.length === 0) {
    return (
      <section className="results-panel network-panel">
        <NetworkHeader matrix={matrix} clusters={clusters} nodeCount={0} edgeCount={0} limited={false} />
        <div className="empty-state compact-empty">
          <Network size={24} aria-hidden="true" />
          <p>No graphable actors found.</p>
        </div>
      </section>
    );
  }

  return (
    <section className="results-panel network-panel" aria-live="polite">
      <NetworkHeader
        matrix={matrix}
        clusters={clusters}
        nodeCount={graph.nodes.length}
        edgeCount={graph.links.length}
        limited={graph.nodes.length < matrix.actors.length}
      />
      {graph.links.length === 0 ? (
        <div className="graph-notice">No edges meet the selected threshold.</div>
      ) : null}
      <ForceGraph nodes={graph.nodes} links={graph.links} />
    </section>
  );
}

function NetworkHeader({
  matrix,
  clusters,
  nodeCount,
  edgeCount,
  limited
}: {
  matrix: MatrixResponse;
  clusters: ClusterResponse;
  nodeCount: number;
  edgeCount: number;
  limited: boolean;
}) {
  return (
    <div className="results-header network-header">
      <div>
        <p className="panel-label">Hierarchical clustering</p>
        <h2>
          {nodeCount}/{matrix.metadata.actor_count} nodes, {edgeCount} edges
        </h2>
      </div>
      <div className="results-actions">
        {limited ? <span className="matrix-note">Limited view</span> : null}
        <span className="metric-label">{metricLabel(clusters.metric)}</span>
      </div>
    </div>
  );
}

function ForceGraph({ nodes, links }: { nodes: GraphNode[]; links: GraphLink[] }) {
  const [layoutNodes, setLayoutNodes] = useState<GraphNode[]>(nodes);
  const [layoutLinks, setLayoutLinks] = useState<GraphLink[]>(links);

  useEffect(() => {
    const nextNodes = nodes.map((node, index) => {
      const angle = (index / Math.max(1, nodes.length)) * Math.PI * 2;
      return {
        ...node,
        x: GRAPH_WIDTH / 2 + Math.cos(angle) * 180,
        y: GRAPH_HEIGHT / 2 + Math.sin(angle) * 180
      };
    });
    const nextLinks = links.map((link) => ({ ...link }));
    const simulation = forceSimulation<GraphNode>(nextNodes)
      .force(
        "link",
        forceLink<GraphNode, GraphLink>(nextLinks)
          .id((node) => node.id)
          .distance((link) => 130 - link.similarity * 75)
          .strength((link) => 0.12 + link.similarity * 0.35)
      )
      .force("charge", forceManyBody().strength(-170))
      .force("center", forceCenter(GRAPH_WIDTH / 2, GRAPH_HEIGHT / 2))
      .force("collide", forceCollide<GraphNode>().radius(24));

    let tickCount = 0;
    simulation.on("tick", () => {
      tickCount += 1;
      if (tickCount % 3 === 0) {
        setLayoutNodes(nextNodes.map((node) => ({ ...node })));
        setLayoutLinks(nextLinks.map((link) => ({ ...link })));
      }
    });
    simulation.on("end", () => {
      setLayoutNodes(nextNodes.map((node) => ({ ...node })));
      setLayoutLinks(nextLinks.map((link) => ({ ...link })));
    });

    return () => {
      simulation.stop();
    };
  }, [links, nodes]);

  return (
    <div className="network-canvas">
      <svg viewBox={`0 0 ${GRAPH_WIDTH} ${GRAPH_HEIGHT}`} role="img" aria-label="Actor similarity network graph">
        <g>
          {layoutLinks.map((link, index) => {
            const source = graphEndpoint(link.source);
            const target = graphEndpoint(link.target);
            if (!source || !target) {
              return null;
            }
            return (
              <line
                key={`${source.id}-${target.id}-${index}`}
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                strokeWidth={1 + link.similarity * 5}
                className="network-edge"
              >
                <title>{`${source.name} to ${target.name}: ${formatScore(link.similarity)}`}</title>
              </line>
            );
          })}
        </g>
        <g>
          {layoutNodes.map((node) => (
            <g key={node.id} transform={`translate(${node.x ?? GRAPH_WIDTH / 2}, ${node.y ?? GRAPH_HEIGHT / 2})`}>
              <circle r={nodeRadius(node)} fill={clusterColor(node.clusterId)} className="network-node" />
              <title>{`${node.name}\nCluster ${node.clusterId}`}</title>
              <text dy={nodeRadius(node) + 13}>{shortActorName(node.name)}</text>
            </g>
          ))}
        </g>
      </svg>
    </div>
  );
}

function useGraphData(
  matrix: MatrixResponse | null,
  clusters: ClusterResponse | null,
  threshold: number,
  nodeLimit: number
): { nodes: GraphNode[]; links: GraphLink[] } {
  return useMemo(() => {
    if (!matrix || !clusters) {
      return { nodes: [], links: [] };
    }

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
      .slice(0, nodeLimit);
    const visibleIndexes = new Set(visibleActors.map((item) => item.index));
    const nodes = visibleActors.map(({ actor, averageSimilarity }) => ({
      id: actor.id,
      name: actor.name,
      clusterId: clusterByActorId.get(actor.id) ?? 0,
      averageSimilarity
    }));
    const links: GraphLink[] = [];

    for (const sourceIndex of visibleIndexes) {
      for (const targetIndex of visibleIndexes) {
        if (sourceIndex >= targetIndex) {
          continue;
        }
        const similarity = clampScore(matrix.matrix[sourceIndex]?.[targetIndex] ?? 0);
        if (similarity > threshold) {
          links.push({
            source: matrix.actors[sourceIndex].id,
            target: matrix.actors[targetIndex].id,
            similarity
          });
        }
      }
    }

    return { nodes, links };
  }, [clusters, matrix, nodeLimit, threshold]);
}

function graphEndpoint(endpoint: string | GraphNode): GraphNode | null {
  return typeof endpoint === "string" ? null : endpoint;
}

function nodeRadius(node: GraphNode): number {
  return 8 + Math.min(12, node.averageSimilarity * 48);
}

function clusterColor(clusterId: number): string {
  if (clusterId <= 0) {
    return "#70808a";
  }
  return CLUSTER_COLORS[(clusterId - 1) % CLUSTER_COLORS.length];
}

function shortActorName(name: string): string {
  return name.length > 18 ? `${name.slice(0, 16)}...` : name;
}

function StatusMessage({ message }: { message: string }) {
  return (
    <div className="status-message error">
      <AlertCircle size={17} aria-hidden="true" />
      <span>{message}</span>
    </div>
  );
}

function clampScore(score: number): number {
  return Math.min(1, Math.max(0, score));
}

function formatScore(score: number): string {
  return `${Math.round(clampScore(score) * 100)}%`;
}

function metricLabel(metric: SimilarityMetric): string {
  if (metric === "jaccard_weighted") {
    return "Weighted Jaccard";
  }
  if (metric === "tactic_weighted_jaccard") {
    return "Tactic weighted";
  }
  if (metric === "software_weighted_jaccard") {
    return "Software weighted";
  }
  return "Jaccard";
}
