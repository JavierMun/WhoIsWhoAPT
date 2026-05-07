import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";

import { formatTactic, techniqueName, techniqueTitle, type TechniqueLookup } from "../api/ttpProfileUtils";
import type { ActorComparisonResponse, ActorEnrichment, ComparisonResult, SoftwareSummary, TacticBreakdown } from "../api/types";

export function ComparisonRankingView({
  comparison,
  techniqueLookup,
  inputSectors = [],
  inputCountries = [],
  actorAliases = {}
}: {
  comparison: ActorComparisonResponse;
  techniqueLookup: TechniqueLookup;
  inputSectors?: string[];
  inputCountries?: string[];
  actorAliases?: Record<string, string>;
}) {
  return (
    <ol className="result-list">
      {comparison.results.map((result, index) => (
        <ResultRow
          key={result.matched_entity_id}
          result={result}
          index={index}
          inputName={comparison.input_name}
          inputSectors={inputSectors}
          inputCountries={inputCountries}
          alias={actorAliases[result.matched_entity_id]}
          techniqueLookup={techniqueLookup}
        />
      ))}
    </ol>
  );
}

function ScoreBadge({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  return (
    <div className="score-badge">
      <span className="score-badge-pct">{pct}<span className="score-badge-unit">%</span></span>
      <span className="score-badge-label">SIMILARITY</span>
      <div className="score-spark" aria-hidden="true">
        <span style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function ResultRow({
  result,
  index,
  inputName,
  inputSectors,
  inputCountries,
  alias,
  techniqueLookup
}: {
  result: ComparisonResult;
  index: number;
  inputName: string;
  inputSectors: string[];
  inputCountries: string[];
  alias?: string;
  techniqueLookup: TechniqueLookup;
}) {
  const enrichment = result.enrichment;

  return (
    <li className="result-row">
      <div className="rank">
        <span className="rank-num">{String(index + 1).padStart(2, "0")}</span>
        <span className="rank-label">RANK</span>
      </div>

      <div className="result-main">
        <div className="result-name-line">
          <h3>{result.matched_entity_name}</h3>
          {alias ? <span className="result-alias">{alias}</span> : null}
        </div>

        <div className="result-pills">
          <span className="meta-pill meta-pill--shared">
            {result.shared_techniques.length} shared TTPs
          </span>
          <span className="meta-pill meta-pill--input">
            {result.unique_to_input.length} {inputName}-only
          </span>
          <span className="meta-pill meta-pill--target">
            {result.unique_to_matched_entity.length} {result.matched_entity_name}-only
          </span>
        </div>

        <TacticBreakdownList items={result.tactic_breakdown} techniqueLookup={techniqueLookup} />

        <SharedContextRow
          enrichment={result.enrichment}
          inputSectors={inputSectors}
          inputCountries={inputCountries}
        />

        <TechniqueBreakdownPanel
          result={result}
          inputName={inputName}
          techniqueLookup={techniqueLookup}
        />

        {result.explanation ? <p className="result-explanation">{result.explanation}</p> : null}

        {result.enrichment ? (
          <ActorContextPanel
            enrichment={result.enrichment}
            matchedName={result.matched_entity_name}
          />
        ) : null}
      </div>

      <ScoreBadge score={result.score} />
    </li>
  );
}

function SoftwarePreview({ software }: { software: SoftwareSummary[] }) {
  if (software.length === 0) return null;
  const visible = software.slice(0, 6).map((item) => item.name);
  const hiddenCount = software.length - visible.length;
  return (
    <p className="software-preview">
      <strong>Shared software</strong> {visible.join(", ")}
      {hiddenCount > 0 ? ` +${hiddenCount} more` : ""}
    </p>
  );
}

function TacticBreakdownList({ items }: { items: TacticBreakdown[]; techniqueLookup?: TechniqueLookup }) {
  const visibleItems = items.filter((item) => item.union_technique_count > 0);
  if (visibleItems.length === 0) return null;

  return (
    <div className="tactic-grid" aria-label="Tactic breakdown">
      {visibleItems.map((item) => (
        <div className="tactic-cell" key={item.tactic}>
          <div className="tactic-cell-header">
            <span className="tactic-cell-name">{formatTactic(item.tactic)}</span>
            <span className="tactic-cell-score">{item.shared_technique_count}/{item.union_technique_count}</span>
          </div>
          <div className="tactic-meter" aria-hidden="true">
            <span style={{ width: `${Math.round(item.score_contribution * 100)}%` }} />
          </div>
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
        {open ? <ChevronDown size={12} aria-hidden="true" /> : <ChevronRight size={12} aria-hidden="true" />}
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

function SharedContextRow({
  enrichment,
  inputSectors,
  inputCountries
}: {
  enrichment: ActorEnrichment | null;
  inputSectors: string[];
  inputCountries: string[];
}) {
  if (!enrichment || (inputSectors.length === 0 && inputCountries.length === 0)) return null;

  const inputSectorSet = new Set(inputSectors.map((s) => s.toLowerCase()));
  const inputCountrySet = new Set(inputCountries.map((c) => c.toLowerCase()));
  const sharedSectors = enrichment.target_sectors.filter((s) => inputSectorSet.has(s.toLowerCase()));
  const sharedCountries = enrichment.target_countries.filter((c) => inputCountrySet.has(c.toLowerCase()));

  if (sharedSectors.length === 0 && sharedCountries.length === 0) return null;

  return (
    <div className="shared-context-row">
      <span className="shared-context-label">Shared targeting</span>
      {sharedSectors.length > 0 ? (
        <span className="shared-context-group">
          <span className="shared-context-type">Sectors</span>
          {sharedSectors.map((s) => (
            <span className="technique-chip shared-context-chip" key={s}>{s}</span>
          ))}
        </span>
      ) : null}
      {sharedCountries.length > 0 ? (
        <span className="shared-context-group">
          <span className="shared-context-type">Countries</span>
          {sharedCountries.map((c) => (
            <span className="technique-chip shared-context-chip" key={c}>{c}</span>
          ))}
        </span>
      ) : null}
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
  const hasDescription = !!enrichment.description;
  if (!hasSectors && !hasCountries && !hasCves && !hasMotivation && !hasDescription) return null;

  return (
    <div className="breakdown-panel">
      <button
        type="button"
        className="breakdown-toggle"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        {open ? <ChevronDown size={12} aria-hidden="true" /> : <ChevronRight size={12} aria-hidden="true" />}
        {matchedName} — actor profile
      </button>

      {open ? (
        <div className="actor-context-body">
          {enrichment.description ? (
            <p className="actor-context-desc">
              {enrichment.description.slice(0, 300)}{enrichment.description.length > 300 ? "…" : ""}
            </p>
          ) : null}
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
                    <span className="technique-chip unknown-chip" key={cve} style={{ fontFamily: "var(--mono)", fontSize: "0.72rem" }}>{cve}</span>
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
