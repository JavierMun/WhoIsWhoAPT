import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";

import { formatTactic, techniqueName, techniqueTitle, type TechniqueLookup } from "../api/ttpProfileUtils";
import type { ActorComparisonResponse, ActorEnrichment, ComparisonResult, TacticBreakdown } from "../api/types";

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

        <InsightLine result={result} inputSectors={inputSectors} />

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

function generateInsight(result: ComparisonResult, inputSectors: string[]): string | null {
  const parts: string[] = [];

  const topTactics = result.tactic_breakdown
    .filter((t) => t.shared_technique_count > 0)
    .sort((a, b) => b.score_contribution - a.score_contribution)
    .slice(0, 3);

  if (topTactics.length > 0) {
    const names = topTactics.map((t) => formatTactic(t.tactic));
    const total = result.shared_techniques.length;
    const level = result.score >= 0.5 ? "Strong overlap" : result.score >= 0.25 ? "Moderate overlap" : "Partial overlap";
    if (names.length === 1) {
      parts.push(`${level} on ${names[0]} (${topTactics[0].shared_technique_count} shared).`);
    } else if (names.length === 2) {
      parts.push(`${level} on ${names[0]} and ${names[1]} (${total} shared techniques).`);
    } else {
      parts.push(`${level} on ${names[0]}, ${names[1]}, and ${names[2]} (${total} shared techniques).`);
    }
  } else if (result.shared_techniques.length > 0) {
    parts.push(`${result.shared_techniques.length} technique${result.shared_techniques.length > 1 ? "s" : ""} in common.`);
  }

  // Pick the single most informative extra signal: sectors > rare techniques > software
  if (inputSectors.length > 0 && result.enrichment) {
    const inputSet = new Set(inputSectors.map((s) => s.toLowerCase()));
    const shared = result.enrichment.target_sectors.filter((s) => inputSet.has(s.toLowerCase()));
    if (shared.length === 1) {
      parts.push(`Both operate against ${shared[0]}.`);
    } else if (shared.length === 2) {
      parts.push(`Both operate against ${shared[0]} and ${shared[1]}.`);
    } else if (shared.length > 2) {
      parts.push(`Both operate against ${shared[0]}, ${shared[1]}, and ${shared.length - 2} more sector${shared.length - 2 > 1 ? "s" : ""}.`);
    }
  }

  if (parts.length < 2 && result.rare_shared_techniques.length >= 2) {
    parts.push(`${result.rare_shared_techniques.length} rare techniques in common — potential capability fingerprint.`);
  } else if (parts.length < 2 && result.rare_shared_techniques.length === 1) {
    parts.push("1 rare technique in common.");
  }

  if (parts.length < 2 && result.shared_software.length > 0) {
    const names = result.shared_software.slice(0, 3).map((sw) => sw.name);
    const extra = result.shared_software.length - names.length;
    parts.push(`Common tooling: ${names.join(", ")}${extra > 0 ? ` +${extra} more` : ""}.`);
  }

  return parts.length > 0 ? parts.slice(0, 2).join(" ") : null;
}

function InsightLine({ result, inputSectors }: { result: ComparisonResult; inputSectors: string[] }) {
  const insight = generateInsight(result, inputSectors);
  if (!insight) return null;
  return (
    <p className="result-insight">
      <span className="result-insight-icon" aria-hidden="true">◈</span>
      {insight}
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
