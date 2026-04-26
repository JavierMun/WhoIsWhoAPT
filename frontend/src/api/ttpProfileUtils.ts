import type { TechniqueListItem } from "./types";

type NavigatorTechnique = {
  techniqueID?: unknown;
  techniqueId?: unknown;
  technique_id?: unknown;
  enabled?: unknown;
};

export type NavigatorLayer = {
  name?: unknown;
  description?: unknown;
  techniques?: unknown;
};

export type TechniqueGroup = {
  tactic: string;
  techniques: TechniqueListItem[];
};

export type TechniqueLookup = Map<string, TechniqueListItem>;

export function parseTechniqueIds(value: string): string[] {
  return sortedTechniqueIds(value.toUpperCase().match(/T\d{4}(?:\.\d{3})?/g) ?? []);
}

export function normalizeTechniqueIds(techniqueIds: string[]): string[] {
  return sortedTechniqueIds(
    techniqueIds
      .map((techniqueId) => techniqueId.trim().toUpperCase())
      .filter((techniqueId) => /^T\d{4}(?:\.\d{3})?$/.test(techniqueId))
  );
}

export function extractNavigatorTechniqueIds(layer: NavigatorLayer): string[] {
  if (!Array.isArray(layer.techniques)) {
    throw new Error("Navigator layer must contain a techniques array.");
  }

  return normalizeTechniqueIds(
    layer.techniques
      .map((item) => {
        const technique = item as NavigatorTechnique;
        if (technique.enabled === false) {
          return "";
        }
        const techniqueId = technique.techniqueID ?? technique.techniqueId ?? technique.technique_id;
        return typeof techniqueId === "string" ? techniqueId : "";
      })
      .filter(Boolean)
  );
}

export function groupTechniquesByTactic(
  techniqueIds: string[],
  techniqueLookup: TechniqueLookup
): TechniqueGroup[] {
  const groups = new Map<string, TechniqueListItem[]>();
  techniqueIds.forEach((techniqueId) => {
    const technique = techniqueLookup.get(techniqueId);
    if (!technique) {
      return;
    }
    groups.set(technique.tactic, [...(groups.get(technique.tactic) ?? []), technique]);
  });

  return Array.from(groups.entries())
    .sort(([left], [right]) => formatTactic(left).localeCompare(formatTactic(right)))
    .map(([tactic, techniques]) => ({
      tactic,
      techniques: techniques.sort((left, right) => left.technique_id.localeCompare(right.technique_id))
    }));
}

export function techniqueLookupFromList(techniques: TechniqueListItem[]): TechniqueLookup {
  return new Map(techniques.map((technique) => [technique.technique_id, technique]));
}

export function techniqueLabel(techniqueId: string, techniqueLookup: TechniqueLookup): string {
  const technique = techniqueLookup.get(techniqueId);
  return technique ? `${technique.technique_id} - ${technique.name}` : techniqueId;
}

export function techniqueTitle(techniqueId: string, techniqueLookup: TechniqueLookup): string {
  const technique = techniqueLookup.get(techniqueId);
  return technique ? `${techniqueLabel(techniqueId, techniqueLookup)}\nTactic: ${formatTactic(technique.tactic)}` : techniqueId;
}

export function unknownTechniqueIds(techniqueIds: string[], validTechniqueIds: Set<string>): string[] {
  return techniqueIds.filter((techniqueId) => !validTechniqueIds.has(techniqueId));
}

export function formatTactic(tactic: string): string {
  return tactic
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((word) => `${word.charAt(0).toUpperCase()}${word.slice(1)}`)
    .join(" ");
}

function sortedTechniqueIds(techniqueIds: string[]): string[] {
  return Array.from(new Set(techniqueIds)).sort((left, right) => left.localeCompare(right));
}
