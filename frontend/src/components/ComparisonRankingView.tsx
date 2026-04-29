import { formatTactic, techniqueLabel, techniqueTitle, type TechniqueLookup } from "../api/ttpProfileUtils";
import type { ActorComparisonResponse, ActorEnrichment, SoftwareSummary, TacticBreakdown } from "../api/types";

export function ComparisonRankingView({
  comparison,
  techniqueLookup
}: {
  comparison: ActorComparisonResponse;
  techniqueLookup: TechniqueLookup;
}) {
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
              <span>{result.unique_to_matched_entity.length} actor-only techniques</span>
              <span>{result.unique_to_input.length} input-only techniques</span>
            </div>
            <TechniquePreview techniques={result.shared_techniques} techniqueLookup={techniqueLookup} />
            {result.explanation ? <p className="result-explanation">{result.explanation}</p> : null}
            <SoftwarePreview software={result.shared_software} />
            <TacticBreakdownList items={result.tactic_breakdown} techniqueLookup={techniqueLookup} />
            {result.enrichment ? <EnrichmentRow enrichment={result.enrichment} /> : null}
          </div>
        </li>
      ))}
    </ol>
  );
}

function TechniquePreview({ techniques, techniqueLookup }: { techniques: string[]; techniqueLookup: TechniqueLookup }) {
  if (techniques.length === 0) {
    return <p className="technique-preview muted">No shared techniques</p>;
  }

  const visible = techniques.slice(0, 8);
  const hiddenCount = techniques.length - visible.length;

  return (
    <p className="technique-preview">
      {visible.map((techniqueId, index) => (
        <span className="technique-label" key={techniqueId} title={techniqueTitle(techniqueId, techniqueLookup)}>
          {index > 0 ? ", " : ""}
          {techniqueLabel(techniqueId, techniqueLookup)}
        </span>
      ))}
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

function TacticBreakdownList({ items, techniqueLookup }: { items: TacticBreakdown[]; techniqueLookup: TechniqueLookup }) {
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
            {item.shared_techniques.length > 0 ? ": " : ""}
            {item.shared_techniques.slice(0, 4).map((techniqueId, index) => (
              <span className="technique-label" key={techniqueId} title={techniqueTitle(techniqueId, techniqueLookup)}>
                {index > 0 ? ", " : ""}
                {techniqueLabel(techniqueId, techniqueLookup)}
              </span>
            ))}
          </p>
        </div>
      ))}
    </div>
  );
}

function EnrichmentRow({ enrichment }: { enrichment: ActorEnrichment }) {
  const hasSectors = enrichment.target_sectors.length > 0;
  const hasCountries = enrichment.target_countries.length > 0;
  const hasCves = enrichment.cves_exploited.length > 0;
  const hasMotivation = !!enrichment.motivation;
  if (!hasSectors && !hasCountries && !hasCves && !hasMotivation) return null;

  return (
    <div className="result-enrichment">
      {hasMotivation ? (
        <span className="enrichment-item">
          <span className="enrichment-label">Motivation</span>
          <span className="technique-chip">{enrichment.motivation}</span>
        </span>
      ) : null}
      {hasSectors ? (
        <span className="enrichment-item">
          <span className="enrichment-label">Sectors</span>
          {enrichment.target_sectors.slice(0, 5).map((s) => (
            <span className="technique-chip" key={s}>{s}</span>
          ))}
          {enrichment.target_sectors.length > 5 ? (
            <span className="technique-chip unknown-chip">+{enrichment.target_sectors.length - 5}</span>
          ) : null}
        </span>
      ) : null}
      {hasCountries ? (
        <span className="enrichment-item">
          <span className="enrichment-label">Countries</span>
          {enrichment.target_countries.slice(0, 5).map((c) => (
            <span className="technique-chip" key={c}>{c}</span>
          ))}
          {enrichment.target_countries.length > 5 ? (
            <span className="technique-chip unknown-chip">+{enrichment.target_countries.length - 5}</span>
          ) : null}
        </span>
      ) : null}
      {hasCves ? (
        <span className="enrichment-item">
          <span className="enrichment-label">CVEs</span>
          {enrichment.cves_exploited.slice(0, 4).map((cve) => (
            <span className="technique-chip unknown-chip" key={cve} style={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{cve}</span>
          ))}
          {enrichment.cves_exploited.length > 4 ? (
            <span className="technique-chip unknown-chip">+{enrichment.cves_exploited.length - 4}</span>
          ) : null}
        </span>
      ) : null}
    </div>
  );
}

function formatScore(score: number): string {
  return `${Math.round(score * 100)}%`;
}
