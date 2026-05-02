import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";

import { formatTactic, techniqueLabel, techniqueName, techniqueTitle, type TechniqueLookup } from "../api/ttpProfileUtils";
import type { ActorComparisonResponse, ActorEnrichment, ComparisonResult, SoftwareSummary, TacticBreakdown } from "../api/types";

export function ComparisonRankingView({
  comparison,
  techniqueLookup
}: {
  comparison: ActorComparisonResponse;
  techniqueLookup: TechniqueLookup;
}) {
  console.log("[ComparisonRankingView] input_name:", comparison.input_name);
  console.log("[ComparisonRankingView] result count:", comparison.results.length);
  if (comparison.results.length > 0) {
    const r = comparison.results[0];
    console.log("[ComparisonRankingView] result[0]:", {
      matched_entity_name: r.matched_entity_name,
      shared_techniques: r.shared_techniques.length,
      unique_to_input: r.unique_to_input.length,
      unique_to_matched_entity: r.unique_to_matched_entity.length,
    });
  }

  return (
    <ol className="result-list">
      {comparison.results.map((result, index) => (
        <ResultRow
          key={result.matched_entity_id}
          result={result}
          index={index}
          inputName={comparison.input_name}
          techniqueLookup={techniqueLookup}
        />
      ))}
    </ol>
  );
}

function ResultRow({
  result,
  index,
  inputName,
  techniqueLookup
}: {
  result: ComparisonResult;
  index: number;
  inputName: string;
  techniqueLookup: TechniqueLookup;
}) {
  return (
    <li className="result-row">
      <div className="rank">{index + 1}</div>
      <div className="result-main">
        <div className="result-title-line">
          <h3>{result.matched_entity_name}</h3>
          <strong>{formatScore(result.score)}</strong>
        </div>
        <div className="result-meta">
          <span>{result.shared_techniques.length} shared TTPs</span>
          <span className="result-meta-sep">·</span>
          <span>{result.unique_to_matched_entity.length} {result.matched_entity_name}-only TTPs</span>
          <span className="result-meta-sep">·</span>
          <span>{result.unique_to_input.length} {inputName}-only TTPs</span>
        </div>
        <TechniqueBreakdownPanel
          result={result}
          inputName={inputName}
          techniqueLookup={techniqueLookup}
        />
        {result.explanation ? <p className="result-explanation">{result.explanation}</p> : null}
        <SoftwarePreview software={result.shared_software} />
        <TacticBreakdownList items={result.tactic_breakdown} techniqueLookup={techniqueLookup} />
        {result.enrichment ? (
          <ActorContextPanel
            enrichment={result.enrichment}
            matchedName={result.matched_entity_name}
          />
        ) : null}
      </div>
    </li>
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
  const visibleItems = items.filter((item) => item.union_technique_count > 0).slice(0, 6);
  if (visibleItems.length === 0) {
    return null;
  }

  return (
    <div className="tactic-breakdown" aria-label="Tactic breakdown">
      {visibleItems.map((item) => (
        <div className="tactic-row" key={item.tactic}>
          <div className="tactic-row-header">
            <strong>{formatTactic(item.tactic)}</strong>
            <span className="tactic-score">{formatScore(item.score_contribution)}</span>
          </div>
          <div className="tactic-meter" aria-hidden="true">
            <span style={{ width: `${Math.round(item.score_contribution * 100)}%` }} />
          </div>
          <p className="tactic-detail">
            <span className="tactic-count">{item.shared_technique_count}/{item.union_technique_count} shared</span>
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

function TechniqueBreakdownPanel({
  result,
  inputName,
  techniqueLookup
}: {
  result: ComparisonResult;
  inputName: string;
  techniqueLookup: TechniqueLookup;
}) {
  const [open, setOpen] = useState(false);
  const hasData =
    result.shared_techniques.length > 0 ||
    result.unique_to_input.length > 0 ||
    result.unique_to_matched_entity.length > 0;

  if (!hasData) return null;

  return (
    <div className="breakdown-panel">
      <button
        type="button"
        className="breakdown-toggle"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        {open ? <ChevronDown size={14} aria-hidden="true" /> : <ChevronRight size={14} aria-hidden="true" />}
        Technique breakdown
      </button>

      {open ? (
        <div className="breakdown-columns">
          <TechniqueColumn
            title={`${inputName}-only`}
            techniques={result.unique_to_input}
            techniqueLookup={techniqueLookup}
            variant="input"
          />
          <TechniqueColumn
            title="Shared"
            techniques={result.shared_techniques}
            techniqueLookup={techniqueLookup}
            variant="shared"
          />
          <TechniqueColumn
            title={`${result.matched_entity_name}-only`}
            techniques={result.unique_to_matched_entity}
            techniqueLookup={techniqueLookup}
            variant="target"
          />
        </div>
      ) : null}
    </div>
  );
}

function TechniqueColumn({
  title,
  techniques,
  techniqueLookup,
  variant
}: {
  title: string;
  techniques: string[];
  techniqueLookup: TechniqueLookup;
  variant: "input" | "shared" | "target";
}) {
  return (
    <div className={`breakdown-col breakdown-col--${variant}`}>
      <div className="breakdown-col-header">
        <span className="breakdown-col-title">{title}</span>
        <span className="breakdown-col-count">{techniques.length}</span>
      </div>
      <ul className="breakdown-technique-list">
        {techniques.length === 0 ? (
          <li className="breakdown-empty">—</li>
        ) : (
          techniques.map((id) => {
            const name = techniqueName(id, techniqueLookup);
            return (
              <li key={id} className="breakdown-technique-item" title={techniqueTitle(id, techniqueLookup)}>
                <span className="breakdown-technique-id">{id}</span>
                {name ? <span className="breakdown-technique-name">{name}</span> : null}
              </li>
            );
          })
        )}
      </ul>
    </div>
  );
}

function ActorContextPanel({
  enrichment,
  matchedName
}: {
  enrichment: ActorEnrichment;
  matchedName: string;
}) {
  const [open, setOpen] = useState(false);
  const hasSectors = enrichment.target_sectors.length > 0;
  const hasCountries = enrichment.target_countries.length > 0;
  const hasCves = enrichment.cves_exploited.length > 0;
  const hasMotivation = !!enrichment.motivation;
  if (!hasSectors && !hasCountries && !hasCves && !hasMotivation) return null;

  return (
    <div className="breakdown-panel">
      <button
        type="button"
        className="breakdown-toggle"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        {open ? <ChevronDown size={14} aria-hidden="true" /> : <ChevronRight size={14} aria-hidden="true" />}
        {matchedName} — actor profile
      </button>

      {open ? (
        <div className="actor-context-body">
          <p className="actor-context-note">
            The following are known attributes of <strong>{matchedName}</strong> — not shared with the source profile.
          </p>
          <div className="actor-context-grid">
            {hasMotivation ? (
              <div className="actor-context-section">
                <span className="actor-context-label">Motivation</span>
                <div className="chip-list">
                  <span className="technique-chip">{enrichment.motivation}</span>
                </div>
              </div>
            ) : null}
            {hasSectors ? (
              <div className="actor-context-section">
                <span className="actor-context-label">Target sectors</span>
                <div className="chip-list">
                  {enrichment.target_sectors.map((s) => (
                    <span className="technique-chip" key={s}>{s}</span>
                  ))}
                </div>
              </div>
            ) : null}
            {hasCountries ? (
              <div className="actor-context-section">
                <span className="actor-context-label">Target countries</span>
                <div className="chip-list">
                  {enrichment.target_countries.map((c) => (
                    <span className="technique-chip" key={c}>{c}</span>
                  ))}
                </div>
              </div>
            ) : null}
            {hasCves ? (
              <div className="actor-context-section">
                <span className="actor-context-label">CVEs exploited</span>
                <div className="chip-list">
                  {enrichment.cves_exploited.map((cve) => (
                    <span
                      className="technique-chip unknown-chip"
                      key={cve}
                      style={{ fontFamily: "monospace", fontSize: "0.75rem" }}
                    >
                      {cve}
                    </span>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function formatScore(score: number): string {
  return `${Math.round(score * 100)}%`;
}
