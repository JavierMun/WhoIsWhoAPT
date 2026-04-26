import { ArrowDown, ArrowLeft, ArrowRight, ArrowUp, RotateCcw, ZoomIn, ZoomOut } from "lucide-react";
import { useMemo, useState } from "react";

import { buildComparisonGraph, clampScore } from "../api/comparisonViewUtils";
import type { ActorComparisonResponse } from "../api/types";

const GRAPH_WIDTH = 820;
const GRAPH_HEIGHT = 480;

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
        <svg viewBox={`0 0 ${GRAPH_WIDTH} ${GRAPH_HEIGHT}`} role="img" aria-label="Current comparison relationship graph">
          <g transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}>
            <g>
              {graph.edges.map((edge) => {
                const targetNode = graph.nodes.find((node) => node.id === edge.targetId);
                if (!sourceNode || !targetNode) {
                  return null;
                }
                return (
                  <line
                    className="comparison-graph-edge"
                    key={edge.targetId}
                    x1={sourceNode.x}
                    y1={sourceNode.y}
                    x2={targetNode.x}
                    y2={targetNode.y}
                    strokeWidth={1.5 + clampScore(edge.score) * 6}
                  >
                    <title>{`${sourceNode.name} to ${targetNode.name}: ${formatScore(edge.score)}`}</title>
                  </line>
                );
              })}
            </g>
            <g>
              {graph.nodes.map((node) => (
                <g key={node.id} transform={`translate(${node.x}, ${node.y})`}>
                  <circle
                    className={node.isSource ? "comparison-graph-node source" : "comparison-graph-node"}
                    r={node.isSource ? 24 : 12 + clampScore(node.score) * 12}
                  />
                  <title>{node.isSource ? node.name : `${node.name}: ${formatScore(node.score)}`}</title>
                  <text dy={node.isSource ? 38 : 28}>{shortName(node.name)}</text>
                </g>
              ))}
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
