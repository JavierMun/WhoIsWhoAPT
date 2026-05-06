import { ArrowDown, ArrowLeft, ArrowRight, ArrowUp, RotateCcw, ZoomIn, ZoomOut } from "lucide-react";
import { useMemo, useState } from "react";

import { buildComparisonGraph, clampScore } from "../api/comparisonViewUtils";
import type { ActorComparisonResponse } from "../api/types";

const GRAPH_WIDTH = 820;
const GRAPH_HEIGHT = 480;

const NODE_COLORS = [
  "#5ee9c1", // success green
  "#6cb6ff", // info blue
  "#ff8a4c", // accent orange
  "#a78bfa", // purple
  "#f5b744", // warn yellow
  "#ff6b6b", // danger red
  "#34d399", // emerald
  "#60a5fa", // sky blue
];

export function ComparisonGraphView({ comparison }: { comparison: ActorComparisonResponse }) {
  const [threshold, setThreshold] = useState(0);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const graph = useMemo(() => buildComparisonGraph(comparison, threshold, GRAPH_WIDTH, GRAPH_HEIGHT), [comparison, threshold]);
  const sourceNode = graph.nodes.find((node) => node.isSource);

  function resetViewport() {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }

  return (
    <div className="comparison-graph-view">
      <div className="comparison-graph-controls">
        <label className="field-group graph-threshold" htmlFor="comparison-graph-threshold">
          <span>Similarity threshold</span>
          <input
            id="comparison-graph-threshold"
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
        <div className="graph-viewport-controls" aria-label="Graph viewport controls">
          <button
            type="button"
            title="Zoom in"
            onClick={() => {
              setZoom((value) => Math.min(1.8, value + 0.15));
            }}
          >
            <ZoomIn size={16} aria-hidden="true" />
          </button>
          <button
            type="button"
            title="Zoom out"
            onClick={() => {
              setZoom((value) => Math.max(0.65, value - 0.15));
            }}
          >
            <ZoomOut size={16} aria-hidden="true" />
          </button>
          <button type="button" title="Reset graph view" onClick={resetViewport}>
            <RotateCcw size={16} aria-hidden="true" />
          </button>
          <button type="button" title="Pan left" onClick={() => setPan((value) => ({ ...value, x: value.x - 28 }))}>
            <ArrowLeft size={16} aria-hidden="true" />
          </button>
          <button type="button" title="Pan right" onClick={() => setPan((value) => ({ ...value, x: value.x + 28 }))}>
            <ArrowRight size={16} aria-hidden="true" />
          </button>
          <button type="button" title="Pan up" onClick={() => setPan((value) => ({ ...value, y: value.y - 28 }))}>
            <ArrowUp size={16} aria-hidden="true" />
          </button>
          <button type="button" title="Pan down" onClick={() => setPan((value) => ({ ...value, y: value.y + 28 }))}>
            <ArrowDown size={16} aria-hidden="true" />
          </button>
        </div>
      </div>

      {graph.hiddenCount > 0 ? (
        <div className="graph-notice">{graph.hiddenCount} matches hidden below the selected threshold.</div>
      ) : null}
      {graph.edges.length === 0 ? (
        <div className="graph-notice">No comparison targets meet the selected threshold. Lower the threshold to show edges.</div>
      ) : null}

      <div className="comparison-graph-canvas">
        <svg className="comparison-graph" viewBox={`0 0 ${GRAPH_WIDTH} ${GRAPH_HEIGHT}`} role="img" aria-label="Current comparison relationship graph">
          <g transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}>
            {/* Edges with % labels */}
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
                        <rect
                          x={mx - 14} y={my - 9}
                          width={28} height={15}
                          rx={4} fill="var(--bg-2)"
                          fillOpacity={0.85}
                        />
                        <text
                          x={mx} y={my + 2}
                          className="graph-edge-label"
                          textAnchor="middle"
                        >{pct}%</text>
                      </>
                    ) : null}
                  </g>
                );
              })}
            </g>
            {/* Nodes */}
            <g>
              {graph.nodes.map((node, i) => {
                const r = node.isSource ? 22 : 10 + clampScore(node.score) * 12;
                const color = node.isSource
                  ? "var(--accent)"
                  : NODE_COLORS[i % NODE_COLORS.length];
                return (
                  <g key={node.id} transform={`translate(${node.x}, ${node.y})`}>
                    <circle
                      r={r}
                      fill={color}
                      fillOpacity={node.isSource ? 0.25 : 0.2}
                      stroke={color}
                      strokeWidth={node.isSource ? 2.5 : 2}
                    />
                    <title>{node.isSource ? node.name : `${node.name}: ${formatScore(node.score)}`}</title>
                    <text
                      dy={r + 14}
                      className="graph-node-label"
                      textAnchor="middle"
                    >{shortName(node.name)}</text>
                    {!node.isSource ? (
                      <text
                        dy={5}
                        className="graph-node-score"
                        textAnchor="middle"
                        fill={color}
                      >{formatScore(node.score)}</text>
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
