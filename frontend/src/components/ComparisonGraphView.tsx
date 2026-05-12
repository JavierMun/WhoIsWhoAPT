import { ArrowDown, ArrowLeft, ArrowRight, ArrowUp, Camera, RotateCcw, ZoomIn, ZoomOut } from "lucide-react";
import { useMemo, useRef, useState } from "react";

import { buildComparisonGraph, clampScore } from "../api/comparisonViewUtils";
import type { ActorComparisonResponse } from "../api/types";

const GRAPH_WIDTH = 820;
const GRAPH_HEIGHT = 480;

const NODE_COLORS = [
  "#5ee9c1",
  "#6cb6ff",
  "#ff8a4c",
  "#a78bfa",
  "#f5b744",
  "#ff6b6b",
  "#34d399",
  "#60a5fa",
];

export function ComparisonGraphView({ comparison }: { comparison: ActorComparisonResponse }) {
  const [threshold, setThreshold] = useState(0);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const svgRef = useRef<SVGSVGElement | null>(null);
  const canvasDragRef = useRef<{ startX: number; startY: number; startPanX: number; startPanY: number } | null>(null);

  const graph = useMemo(
    () => buildComparisonGraph(comparison, threshold, GRAPH_WIDTH, GRAPH_HEIGHT),
    [comparison, threshold]
  );
  const sourceNode = graph.nodes.find((node) => node.isSource);

  function resetViewport() {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }

  function handleCanvasPointerDown(e: React.PointerEvent<SVGSVGElement>) {
    canvasDragRef.current = { startX: e.clientX, startY: e.clientY, startPanX: pan.x, startPanY: pan.y };
  }

  function handleCanvasPointerMove(e: React.PointerEvent<SVGSVGElement>) {
    const cd = canvasDragRef.current;
    if (!cd) return;
    setPan({ x: cd.startPanX + (e.clientX - cd.startX), y: cd.startPanY + (e.clientY - cd.startY) });
  }

  function handleCanvasPointerUp() {
    canvasDragRef.current = null;
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
    bg.setAttribute("fill", "#141b24");
    clone.insertBefore(bg, clone.firstChild);
    const style = document.createElementNS("http://www.w3.org/2000/svg", "style");
    style.textContent = `
      text { font-family: ui-sans-serif, system-ui, sans-serif; }
      .graph-node-label { fill: #e8edf2; font-size: 11px; font-weight: 600; paint-order: stroke; stroke: #141b24; stroke-width: 3.5px; }
      .graph-node-score { font-size: 10px; font-weight: 700; paint-order: stroke; stroke: #141b24; stroke-width: 2px; }
      .graph-edge-label { fill: #e8edf2; font-size: 10px; font-weight: 700; font-family: monospace; }
      .comparison-graph-edge { stroke: rgba(255,255,255,0.3); }
    `;
    clone.insertBefore(style, clone.firstChild);
    const svgData = new XMLSerializer().serializeToString(clone);
    const blob = new Blob([svgData], { type: "image/svg+xml" });
    const url = URL.createObjectURL(blob);
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = GRAPH_WIDTH * 2;
      canvas.height = GRAPH_HEIGHT * 2;
      const ctx = canvas.getContext("2d");
      if (!ctx) { URL.revokeObjectURL(url); return; }
      ctx.scale(2, 2);
      ctx.fillStyle = "#141b24";
      ctx.fillRect(0, 0, GRAPH_WIDTH, GRAPH_HEIGHT);
      ctx.drawImage(img, 0, 0);
      URL.revokeObjectURL(url);
      canvas.toBlob((pngBlob) => {
        if (!pngBlob) return;
        const pngUrl = URL.createObjectURL(pngBlob);
        const a = document.createElement("a");
        a.href = pngUrl;
        a.download = `${comparison.input_name}-graph.png`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(pngUrl);
      }, "image/png");
    };
    img.src = url;
  }

  return (
    <div className="comparison-graph-view">
      <div className="comparison-graph-controls">
        <label className="field-group graph-threshold" htmlFor="comparison-graph-threshold">
          <span>Similarity threshold</span>
          <input
            id="comparison-graph-threshold"
            type="range" min={0} max={1} step={0.01} value={threshold}
            onChange={(e) => setThreshold(Number(e.target.value))}
          />
          <span className="field-hint">{formatScore(threshold)} and higher</span>
        </label>
      </div>

      {graph.hiddenCount > 0 ? (
        <div className="graph-notice">{graph.hiddenCount} matches hidden below the selected threshold.</div>
      ) : null}
      {graph.edges.length === 0 ? (
        <div className="graph-notice">No comparison targets meet the selected threshold. Lower the threshold to show edges.</div>
      ) : null}

      <div className="comparison-graph-canvas">
        <div className="graph-viewport-controls" aria-label="Graph viewport controls">
          <button type="button" title="Export as PNG image" onClick={exportAsImage}>
            <Camera size={16} aria-hidden="true" />
          </button>
          <button type="button" title="Zoom in" onClick={() => setZoom((v) => Math.min(2.5, v + 0.15))}>
            <ZoomIn size={16} aria-hidden="true" />
          </button>
          <button type="button" title="Zoom out" onClick={() => setZoom((v) => Math.max(0.15, v - 0.15))}>
            <ZoomOut size={16} aria-hidden="true" />
          </button>
          <button type="button" title="Reset graph view" onClick={resetViewport}>
            <RotateCcw size={16} aria-hidden="true" />
          </button>
          <button type="button" title="Pan left" onClick={() => setPan((v) => ({ ...v, x: v.x - 28 }))}>
            <ArrowLeft size={16} aria-hidden="true" />
          </button>
          <button type="button" title="Pan right" onClick={() => setPan((v) => ({ ...v, x: v.x + 28 }))}>
            <ArrowRight size={16} aria-hidden="true" />
          </button>
          <button type="button" title="Pan up" onClick={() => setPan((v) => ({ ...v, y: v.y - 28 }))}>
            <ArrowUp size={16} aria-hidden="true" />
          </button>
          <button type="button" title="Pan down" onClick={() => setPan((v) => ({ ...v, y: v.y + 28 }))}>
            <ArrowDown size={16} aria-hidden="true" />
          </button>
        </div>
        <svg
          ref={svgRef}
          className="comparison-graph"
          viewBox={`0 0 ${GRAPH_WIDTH} ${GRAPH_HEIGHT}`}
          role="img"
          aria-label="Current comparison relationship graph"
          style={{ cursor: canvasDragRef.current ? "grabbing" : "grab" }}
          onPointerDown={handleCanvasPointerDown}
          onPointerMove={handleCanvasPointerMove}
          onPointerUp={handleCanvasPointerUp}
          onPointerLeave={handleCanvasPointerUp}
        >
          <g transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}>
            <g>
              {graph.edges.map((edge) => {
                const targetNode = graph.nodes.find((node) => node.id === edge.targetId);
                if (!sourceNode || !targetNode) return null;
                const pct = Math.round(clampScore(edge.score) * 100);
                const mx = (sourceNode.x + targetNode.x) / 2;
                const my = (sourceNode.y + targetNode.y) / 2;
                const opacity = 0.3 + clampScore(edge.score) * 0.7;
                return (
                  <g key={edge.targetId}>
                    <line
                      className="comparison-graph-edge"
                      x1={sourceNode.x} y1={sourceNode.y}
                      x2={targetNode.x} y2={targetNode.y}
                      strokeWidth={1 + clampScore(edge.score) * 4}
                      strokeOpacity={opacity}
                    />
                    {pct > 0 ? (
                      <>
                        <rect x={mx - 14} y={my - 9} width={28} height={15} rx={4} fill="var(--bg-2)" fillOpacity={0.85} />
                        <text x={mx} y={my + 2} className="graph-edge-label" textAnchor="middle">{pct}%</text>
                      </>
                    ) : null}
                  </g>
                );
              })}
            </g>
            <g>
              {graph.nodes.map((node, i) => {
                const r = node.isSource ? 22 : 10 + clampScore(node.score) * 12;
                const color = node.isSource ? "var(--accent)" : NODE_COLORS[i % NODE_COLORS.length];
                return (
                  <g key={node.id} transform={`translate(${node.x}, ${node.y})`}>
                    <circle r={r} fill={color} fillOpacity={node.isSource ? 0.25 : 0.2} stroke={color} strokeWidth={node.isSource ? 2.5 : 2} />
                    <title>{node.isSource ? node.name : `${node.name}: ${formatScore(node.score)}`}</title>
                    <text dy={r + 14} className="graph-node-label" textAnchor="middle">{shortName(node.name)}</text>
                    {!node.isSource ? (
                      <text dy={5} className="graph-node-score" textAnchor="middle" fill={color}>{formatScore(node.score)}</text>
                    ) : (
                      <text dy={6} className="graph-node-score" textAnchor="middle" fill="var(--accent)">SRC</text>
                    )}
                  </g>
                );
              })}
            </g>
          </g>
        </svg>
      </div>
    </div>
  );
}

function formatScore(score: number): string {
  return `${Math.round(clampScore(score) * 100)}%`;
}

function shortName(name: string): string {
  return name.length > 20 ? `${name.slice(0, 18)}...` : name;
}
