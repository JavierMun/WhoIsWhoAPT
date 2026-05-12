import { useState } from "react";

import { comparisonHeatColor, visibleComparisonResults } from "../api/comparisonViewUtils";
import type { ActorComparisonResponse } from "../api/types";

const DEFAULT_HEATMAP_LIMIT = 24;
const MAX_HEATMAP_LIMIT = 80;

export function ComparisonHeatmapView({ comparison }: { comparison: ActorComparisonResponse }) {
  const [visibleLimit, setVisibleLimit] = useState(Math.min(DEFAULT_HEATMAP_LIMIT, comparison.results.length));
  const visibleResults = visibleComparisonResults(comparison.results, visibleLimit);
  const isLimited = visibleResults.length < comparison.results.length;

  return (
    <div className="comparison-heatmap-view">
      <div className="comparison-view-controls">
        <label className="field-group compact-field" htmlFor="comparison-heatmap-limit">
          <span>Visible results</span>
          <input
            id="comparison-heatmap-limit"
            type="number"
            min={1}
            max={Math.min(MAX_HEATMAP_LIMIT, comparison.results.length)}
            value={visibleLimit}
            onChange={(event) => {
              const nextValue = Number(event.target.value);
              setVisibleLimit(
                Number.isFinite(nextValue)
                  ? Math.min(Math.min(MAX_HEATMAP_LIMIT, comparison.results.length), Math.max(1, nextValue))
                  : DEFAULT_HEATMAP_LIMIT
              );
            }}
          />
        </label>
        {isLimited ? <span className="matrix-note">Limited to strongest visible matches</span> : null}
      </div>

      <div className="comparison-heatmap-scroll">
        <table className="comparison-heatmap-table" aria-label="Current comparison heatmap">
          <thead>
            <tr>
              <th className="comparison-source-cell" scope="col">
                Source
              </th>
              {visibleResults.map((result) => (
                <th className="comparison-match-cell" key={result.matched_entity_id} scope="col" title={result.matched_entity_name}>
                  <span>{result.matched_entity_name}</span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            <tr>
              <th className="comparison-source-cell" scope="row" title={comparison.input_name}>
                {comparison.input_name}
              </th>
              {visibleResults.map((result) => (
                <td
                  className="comparison-score-cell"
                  key={result.matched_entity_id}
                  style={{ backgroundColor: comparisonHeatColor(result.score), color: result.score >= 0.62 ? "#ffffff" : "#172026" }}
                  title={`${comparison.input_name} to ${result.matched_entity_name}: ${formatScore(result.score)}`}
                >
                  {formatScore(result.score)}
                </td>
              ))}
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}

function formatScore(score: number): string {
  return `${Math.round(score * 100)}%`;
}
