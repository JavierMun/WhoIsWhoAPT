import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation
} from "d3-force";
import { AlertCircle, ArrowDown, ArrowLeft, ArrowRight, ArrowUp, Camera, Loader2, Network, RefreshCw, RotateCcw, ZoomIn, ZoomOut } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { computeMatrix, getClusters, getMatrixResult } from "../api/client";
import { buildGraphData, type GraphData, type GraphLink, type GraphNode } from "../api/graphUtils";
import type { ClusterResponse, MatrixResponse, SimilarityMetric } from "../api/types";

const DEFAULT_THRESHOLD = 0.15;
const DEFAULT_NODE_LIMIT = 60;
const MAX_NODE_LIMIT = 100;
const GRAPH_WIDTH = 920;
const GRAPH_HEIGHT = 560;
const CLUSTER_COLORS = ["#136f63", "#7c3aed", "#c2410c", "#2563eb", "#a21caf", "#0f766e", "#b45309", "#be123c"];

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
      setClusters(await getClusters(DEFAULT_THRESHOLD));
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
              <option value="holistic">Holistic</option>
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
  const canExport = Boolean(matrix && clusters && graph.nodes.length > 0);

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
        edgeCount={graph.totalEdgeCount}
        renderedEdgeCount={graph.links.length}
        limited={graph.nodes.length < matrix.actors.length}
        canExport={canExport}
        onExport={() => downloadGraphExport(matrix, clusters, graph, threshold)}
      />
      {graph.omittedEdgeCount > 0 ? (
        <div className="graph-notice">{graph.omittedEdgeCount} weaker edges hidden to keep the graph readable.</div>
      ) : null}
      {graph.links.length === 0 ? (
        <div className="graph-notice">No edges meet the selected threshold. Lower the threshold to reveal weaker links.</div>
      ) : null}
      <ForceGraph key={graph.nodes.map((node) => node.id).join("|")} nodes={graph.nodes} links={graph.links} />
    </section>
  );
}

function NetworkHeader({
  matrix,
  clusters,
  nodeCount,
  edgeCount,
  renderedEdgeCount,
  limited,
  canExport,
  onExport
}: {
  matrix: MatrixResponse;
  clusters: ClusterResponse;
  nodeCount: number;
  edgeCount: number;
  renderedEdgeCount?: number;
  limited: boolean;
  canExport?: boolean;
  onExport?: () => void;
}) {
  return (
    <div className="results-header network-header">
      <div>
        <p className="panel-label">Hierarchical clustering</p>
        <h2>
          {nodeCount}/{matrix.metadata.actor_count} nodes, {renderedEdgeCount ?? edgeCount}/{edgeCount} edges
        </h2>
      </div>
      <div className="results-actions">
        {limited ? <span className="matrix-note">Limited view</span> : null}
        <span className="metric-label">{metricLabel(clusters.metric)}</span>
        {/* JSON export removed — use screenshot export in graph controls */}
      </div>
    </div>
  );
}

function ForceGraph({ nodes, links }: { nodes: GraphNode[]; links: GraphLink[] }) {
  const [layoutNodes, setLayoutNodes] = useState<GraphNode[]>(nodes);
  const [layoutLinks, setLayoutLinks] = useState<GraphLink[]>(links);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const simulationRef = useRef<{ alpha: (v: number) => any; alphaTarget: (v: number) => any; restart: () => any; stop: () => any } | null>(null);
  const liveNodesRef = useRef<GraphNode[]>([]);
  const dragRef = useRef<{ nodeId: string; startX: number; startY: number; nodeX: number; nodeY: number } | null>(null);
  const canvasDragRef = useRef<{ startX: number; startY: number; startPanX: number; startPanY: number } | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

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
    liveNodesRef.current = nextNodes;

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

    simulationRef.current = simulation;

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
      simulationRef.current = null;
    };
  }, [links, nodes]);

  function svgPoint(e: React.PointerEvent<SVGSVGElement>): { x: number; y: number } {
    const svg = svgRef.current;
    if (!svg) return { x: e.clientX, y: e.clientY };
    const pt = svg.createSVGPoint();
    pt.x = e.clientX;
    pt.y = e.clientY;
    const ctm = svg.getScreenCTM();
    const inv = ctm?.inverse();
    if (!inv) return { x: e.clientX, y: e.clientY };
    const transformed = pt.matrixTransform(inv);
    // Adjust for pan + zoom
    return {
      x: (transformed.x - pan.x) / zoom,
      y: (transformed.y - pan.y) / zoom
    };
  }

  function handleNodePointerDown(e: React.PointerEvent<SVGGElement>, nodeId: string) {
    e.stopPropagation();
    const node = liveNodesRef.current.find((n) => n.id === nodeId);
    if (!node) return;
    const pt = svgPoint(e as unknown as React.PointerEvent<SVGSVGElement>);
    dragRef.current = { nodeId, startX: pt.x, startY: pt.y, nodeX: node.x ?? 0, nodeY: node.y ?? 0 };
    // Fix the node in place so simulation doesn't move it
    (node as Record<string, unknown>).fx = node.x;
    (node as Record<string, unknown>).fy = node.y;
    simulationRef.current?.alphaTarget(0.1).restart();
  }

  function handleSvgPointerDown(e: React.PointerEvent<SVGSVGElement>) {
    // Only start canvas drag when clicking the background (not a node)
    // Node pointerdown stops propagation, so this only fires for background clicks
    if (dragRef.current) return;
    canvasDragRef.current = {
      startX: e.clientX,
      startY: e.clientY,
      startPanX: pan.x,
      startPanY: pan.y
    };
  }

  function handleSvgPointerMove(e: React.PointerEvent<SVGSVGElement>) {
    // Canvas drag (background pan)
    const canvas = canvasDragRef.current;
    if (canvas) {
      const dx = e.clientX - canvas.startX;
      const dy = e.clientY - canvas.startY;
      setPan({ x: canvas.startPanX + dx, y: canvas.startPanY + dy });
      return;
    }

    const drag = dragRef.current;
    if (!drag) return;
    const pt = svgPoint(e);
    const dx = pt.x - drag.startX;
    const dy = pt.y - drag.startY;
    const node = liveNodesRef.current.find((n) => n.id === drag.nodeId);
    if (!node) return;
    (node as Record<string, unknown>).fx = drag.nodeX + dx;
    (node as Record<string, unknown>).fy = drag.nodeY + dy;
    simulationRef.current?.alphaTarget(0.1).restart();
  }

  function fitToView() {
    const nodes = layoutNodes.filter((n) => n.x != null && n.y != null);
    if (nodes.length === 0) return;
    const PADDING = 48;
    const minX = Math.min(...nodes.map((n) => n.x ?? 0));
    const maxX = Math.max(...nodes.map((n) => n.x ?? 0));
    const minY = Math.min(...nodes.map((n) => n.y ?? 0));
    const maxY = Math.max(...nodes.map((n) => n.y ?? 0));
    const contentW = maxX - minX + PADDING * 2;
    const contentH = maxY - minY + PADDING * 2;
    const scale = Math.min(GRAPH_WIDTH / contentW, GRAPH_HEIGHT / contentH, 1.5);
    const panX = (GRAPH_WIDTH - contentW * scale) / 2 - (minX - PADDING) * scale;
    const panY = (GRAPH_HEIGHT - contentH * scale) / 2 - (minY - PADDING) * scale;
    setZoom(Math.round(scale * 100) / 100);
    setPan({ x: Math.round(panX), y: Math.round(panY) });
  }

  function handleSvgPointerUp() {
    if (canvasDragRef.current) {
      canvasDragRef.current = null;
      return;
    }
    const drag = dragRef.current;
    if (!drag) return;
    simulationRef.current?.alphaTarget(0);
    dragRef.current = null;
  }

  function exportAsImage() {
    const svg = svgRef.current;
    if (!svg) return;

    const clone = svg.cloneNode(true) as SVGSVGElement;
    clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    clone.setAttribute("width", String(GRAPH_WIDTH));
    clone.setAttribute("height", String(GRAPH_HEIGHT));

    const bg = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    bg.setAttribute("width", String(GRAPH_WIDTH));
    bg.setAttribute("height", String(GRAPH_HEIGHT));
    bg.setAttribute("fill", "#0e1318");
    clone.insertBefore(bg, clone.firstChild);

    const style = document.createElementNS("http://www.w3.org/2000/svg", "style");
    style.textContent = `
      text { font-family: ui-sans-serif, system-ui, sans-serif; }
      .network-node-label { fill: #e8edf2; font-size: 10px; font-weight: 500; paint-order: stroke; stroke: #0e1318; stroke-width: 3px; }
      .network-edge { stroke: rgba(255,255,255,0.35); }
      .network-edge-label { fill: #a8b4c0; font-size: 9px; font-weight: 700; font-family: monospace; }
    `;
    clone.insertBefore(style, clone.firstChild);

    const svgData = new XMLSerializer().serializeToString(clone);
    const blob = new Blob([svgData], { type: "image/svg+xml" });
    const url = URL.createObjectURL(blob);

    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement("canvas");
      const scale = 2;
      canvas.width = GRAPH_WIDTH * scale;
      canvas.height = GRAPH_HEIGHT * scale;
      const ctx = canvas.getContext("2d");
      if (!ctx) { URL.revokeObjectURL(url); return; }
      ctx.scale(scale, scale);
      ctx.fillStyle = "#0e1318";
      ctx.fillRect(0, 0, GRAPH_WIDTH, GRAPH_HEIGHT);
      ctx.drawImage(img, 0, 0);
      URL.revokeObjectURL(url);
      canvas.toBlob((pngBlob) => {
        if (!pngBlob) return;
        const pngUrl = URL.createObjectURL(pngBlob);
        const a = document.createElement("a");
        a.href = pngUrl;
        a.download = "whoiswhoapt-network.png";
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(pngUrl);
      }, "image/png");
    };
    img.src = url;
  }

  return (
    <div className="network-canvas">
      <div className="graph-viewport-controls network-viewport-controls" aria-label="Network graph viewport controls">
        <button
          type="button"
          title="Export graph as PNG image"
          onClick={exportAsImage}
        >
          <Camera size={16} aria-hidden="true" />
        </button>
        <button
          type="button"
          title="Fit all nodes in view"
          onClick={fitToView}
          style={{ fontWeight: 700, fontSize: "0.7rem", width: "auto", padding: "0 8px" }}
        >
          Fit
        </button>
        <button
          type="button"
          title="Zoom in"
          onClick={() => setZoom((v) => Math.min(2.5, v + 0.15))}
        >
          <ZoomIn size={16} aria-hidden="true" />
        </button>
        <button
          type="button"
          title="Zoom out"
          onClick={() => setZoom((v) => Math.max(0.15, v - 0.15))}
        >
          <ZoomOut size={16} aria-hidden="true" />
        </button>
        <button
          type="button"
          title="Reset graph view"
          onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}
        >
          <RotateCcw size={16} aria-hidden="true" />
        </button>
        <button type="button" title="Pan left" onClick={() => setPan((value) => ({ ...value, x: value.x - 36 }))}>
          <ArrowLeft size={16} aria-hidden="true" />
        </button>
        <button type="button" title="Pan right" onClick={() => setPan((value) => ({ ...value, x: value.x + 36 }))}>
          <ArrowRight size={16} aria-hidden="true" />
        </button>
        <button type="button" title="Pan up" onClick={() => setPan((value) => ({ ...value, y: value.y - 36 }))}>
          <ArrowUp size={16} aria-hidden="true" />
        </button>
        <button type="button" title="Pan down" onClick={() => setPan((value) => ({ ...value, y: value.y + 36 }))}>
          <ArrowDown size={16} aria-hidden="true" />
        </button>
      </div>
      <svg
        ref={svgRef}
        viewBox={`0 0 ${GRAPH_WIDTH} ${GRAPH_HEIGHT}`}
        role="img"
        aria-label="Actor similarity network graph"
        style={{ cursor: canvasDragRef.current ? "grabbing" : dragRef.current ? "grabbing" : "grab" }}
        onPointerDown={handleSvgPointerDown}
        onPointerMove={handleSvgPointerMove}
        onPointerUp={handleSvgPointerUp}
        onPointerLeave={handleSvgPointerUp}
      >
        <g transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}>
          <g>
          {/* Edges */}
          {layoutLinks.map((link, index) => {
            const source = graphEndpoint(link.source);
            const target = graphEndpoint(link.target);
            if (!source || !target) return null;
            const mx = ((source.x ?? 0) + (target.x ?? 0)) / 2;
            const my = ((source.y ?? 0) + (target.y ?? 0)) / 2;
            const pct = Math.round(clampScore(link.similarity) * 100);
            const opacity = 0.25 + clampScore(link.similarity) * 0.75;
            return (
              <g key={`${source.id}-${target.id}-${index}`}>
                <line
                  x1={source.x} y1={source.y}
                  x2={target.x} y2={target.y}
                  strokeWidth={1 + link.similarity * 4}
                  className="network-edge"
                  strokeOpacity={opacity}
                />
                {pct >= 10 ? (
                  <>
                    <rect
                      x={mx - 14} y={my - 8} width={28} height={14}
                      rx={3} fill="var(--bg-2)" fillOpacity={0.85}
                    />
                    <text x={mx} y={my + 4} className="network-edge-label" textAnchor="middle">
                      {pct}%
                    </text>
                  </>
                ) : null}
              </g>
            );
          })}
          </g>
          <g>
          {/* Nodes */}
          {layoutNodes.map((node) => {
            const r = nodeRadius(node);
            const color = clusterColor(node.clusterId);
            return (
              <g
                key={node.id}
                transform={`translate(${node.x ?? GRAPH_WIDTH / 2}, ${node.y ?? GRAPH_HEIGHT / 2})`}
                style={{ cursor: "grab" }}
                onPointerDown={(e) => handleNodePointerDown(e, node.id)}
              >
                {/* Glow ring */}
                <circle r={r + 2} fill={color} fillOpacity={0.15} />
                <circle r={r} fill={color} fillOpacity={0.85} className="network-node" />
                <title>{`${node.name} · Cluster ${node.clusterId}`}</title>
                {/* Name label below node */}
                <text
                  dy={r + 14}
                  className="network-node-label"
                  textAnchor="middle"
                >
                  {shortActorName(node.name)}
                </text>
              </g>
            );
          })}
          </g>
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
): GraphData {
  return useMemo(() => {
    return buildGraphData(matrix, clusters, threshold, nodeLimit);
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

function downloadGraphExport(
  matrix: MatrixResponse,
  clusters: ClusterResponse,
  graph: ReturnType<typeof buildGraphData>,
  threshold: number
) {
  const payload = {
    metadata: {
      source: matrix.metadata.source,
      metric: matrix.metadata.metric,
      matrix_generated_at: matrix.metadata.generated_at,
      cluster_generated_at: clusters.generated_at,
      edge_threshold: threshold,
      cluster_min_similarity: clusters.min_similarity,
      actor_count: matrix.metadata.actor_count,
      node_count: graph.nodes.length,
      edge_count: graph.totalEdgeCount,
      rendered_edge_count: graph.links.length
    },
    nodes: graph.nodes.map((node) => ({
      id: node.id,
      name: node.name,
      cluster_id: node.clusterId,
      average_similarity: node.averageSimilarity
    })),
    edges: graph.links.map((link) => ({
      source: endpointId(link.source),
      target: endpointId(link.target),
      similarity: link.similarity
    }))
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `actor-network-${matrix.metadata.metric}.json`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function endpointId(endpoint: string | GraphNode): string {
  return typeof endpoint === "string" ? endpoint : endpoint.id;
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
