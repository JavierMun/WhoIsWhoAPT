import type { ActorComparisonResponse, SoftwareSummary, TacticBreakdown } from "../api/types";

export function ComparisonRankingView({ comparison }: { comparison: ActorComparisonResponse }) {
  return (
    <ol className="result-list">
      {comparison.results.map((result, index) => (
        <li className="result-row" key={result.matched_entity_id}>
          <div className="rank">{index + 1}</div>
          <div className="result-main">
            <div className="result-title-line">
              <h3>{result.matched_entity_name}</h3>
              <strong>{formatScore(result.score)}</strong>
            </div>
            <div className="result-meta">
              <span>{result.shared_techniques.length} shared techniques</span>
              <span>{result.unique_to_matched_entity.length} unique matched</span>
              <span>{result.unique_to_input.length} unique input</span>
            </div>
            <TechniquePreview techniques={result.shared_techniques} />
            <SoftwarePreview software={result.shared_software} />
            <TacticBreakdownList items={result.tactic_breakdown} />
          </div>
        </li>
      ))}
    </ol>
  );
}

function TechniquePreview({ techniques }: { techniques: string[] }) {
  if (techniques.length === 0) {
    return <p className="technique-preview muted">No shared techniques</p>;
  }

  const visible = techniques.slice(0, 8);
  const hiddenCount = techniques.length - visible.length;

  return (
    <p className="technique-preview">
      {visible.join(", ")}
      {hiddenCount > 0 ? ` +${hiddenCount} more` : ""}
    </p>
  );
}

function SoftwarePreview({ software }: { software: SoftwareSummary[] }) {
  if (software.length === 0) {
    return null;
  }

  const visible = software.slice(0, 6).map((item) => item.name);
  const hiddenCount = software.length - visible.length;

  return (
    <p className="software-preview">
      <strong>Shared software</strong> {visible.join(", ")}
      {hiddenCount > 0 ? ` +${hiddenCount} more` : ""}
    </p>
  );
}

function TacticBreakdownList({ items }: { items: TacticBreakdown[] }) {
  const visibleItems = items.filter((item) => item.union_technique_count > 0).slice(0, 4);
  if (visibleItems.length === 0) {
    return null;
  }

  return (
    <div className="tactic-breakdown" aria-label="Tactic breakdown">
      {visibleItems.map((item) => (
        <div className="tactic-row" key={item.tactic}>
          <div className="tactic-row-header">
            <strong>{formatTactic(item.tactic)}</strong>
            <span>{formatScore(item.score_contribution)}</span>
          </div>
          <div className="tactic-meter" aria-hidden="true">
            <span style={{ width: `${Math.round(item.score_contribution * 100)}%` }} />
          </div>
          <p>
            {item.shared_technique_count}/{item.union_technique_count} shared
            {item.shared_techniques.length > 0 ? `: ${item.shared_techniques.slice(0, 4).join(", ")}` : ""}
          </p>
        </div>
      ))}
    </div>
  );
}

function formatScore(score: number): string {
  return `${Math.round(score * 100)}%`;
}

function formatTactic(tactic: string): string {
  return tactic
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((word) => `${word.charAt(0).toUpperCase()}${word.slice(1)}`)
    .join(" ");
}
