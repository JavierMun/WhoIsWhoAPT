import { describe, expect, it } from "vitest";

import {
  extractNavigatorTechniqueIds,
  groupTechniquesByTactic,
  normalizeTechniqueIds,
  parseTechniqueIds,
  splitTactics,
  techniqueLabel,
  techniqueLookupFromList,
  techniqueName,
  techniqueTitle,
  unknownTechniqueIds
} from "./ttpProfileUtils";
import type { TechniqueListItem } from "./types";

describe("TTP profile utilities", () => {
  it("parses pasted technique IDs in uppercase sorted order", () => {
    expect(parseTechniqueIds("t1105, T1059\nnoise t1059.001")).toEqual(["T1059", "T1059.001", "T1105"]);
  });

  it("normalizes technique IDs and drops invalid tokens", () => {
    expect(normalizeTechniqueIds([" t1059 ", "abc", "T1105", "t1059"])).toEqual(["T1059", "T1105"]);
  });

  it("extracts enabled Navigator technique IDs", () => {
    expect(
      extractNavigatorTechniqueIds({
        techniques: [
          { techniqueID: "t1059" },
          { techniqueId: "T1105", enabled: false },
          { technique_id: "T1027" }
        ]
      })
    ).toEqual(["T1027", "T1059"]);
  });

  it("reports unknown technique IDs", () => {
    expect(unknownTechniqueIds(["T1059", "T9999"], new Set(["T1059"]))).toEqual(["T9999"]);
  });

  it("groups selected techniques by tactic", () => {
    const lookup = new Map<string, TechniqueListItem>([
      ["T1059", technique("T1059", "Command and Scripting Interpreter", "execution")],
      ["T1105", technique("T1105", "Ingress Tool Transfer", "command-and-control")]
    ]);

    expect(groupTechniquesByTactic(["T1105", "T1059"], lookup)).toEqual([
      { tactic: "command-and-control", techniques: [technique("T1105", "Ingress Tool Transfer", "command-and-control")] },
      { tactic: "execution", techniques: [technique("T1059", "Command and Scripting Interpreter", "execution")] }
    ]);
  });

  it("formats technique labels and tactic titles from metadata", () => {
    const lookup = techniqueLookupFromList([
      technique("T1059", "Command and Scripting Interpreter", "execution"),
      technique("T1059.001", "PowerShell", "execution")
    ]);

    expect(techniqueLabel("T1059", lookup)).toBe("T1059 — Command and Scripting Interpreter");
    expect(techniqueLabel("T9999", lookup)).toBe("T9999");
    expect(techniqueTitle("T1059.001", lookup)).toBe("T1059.001 — PowerShell\nTactic: Execution");
  });
});

function technique(technique_id: string, name: string, tactic: string, is_subtechnique = false, parent_id: string | null = null): TechniqueListItem {
  return { technique_id, name, tactic, is_subtechnique, parent_id };
}

describe("splitTactics", () => {
  it("splits a single tactic", () => {
    expect(splitTactics("execution")).toEqual(["execution"]);
  });

  it("splits comma-separated tactics and trims whitespace", () => {
    expect(splitTactics("execution, persistence")).toEqual(["execution", "persistence"]);
  });

  it("lowercases all tactics", () => {
    expect(splitTactics("Execution")).toEqual(["execution"]);
  });

  it("filters empty strings", () => {
    expect(splitTactics("")).toEqual([]);
  });
});

describe("techniqueName", () => {
  it("returns empty string when technique not in lookup", () => {
    const lookup = techniqueLookupFromList([]);
    expect(techniqueName("T9999", lookup)).toBe("");
  });

  it("returns empty string when name equals the ID (bad data guard)", () => {
    const lookup = techniqueLookupFromList([technique("T1008", "T1008", "command-and-control")]);
    expect(techniqueName("T1008", lookup)).toBe("");
  });

  it("returns the technique name for a top-level technique", () => {
    const lookup = techniqueLookupFromList([technique("T1059", "Command and Scripting Interpreter", "execution")]);
    expect(techniqueName("T1059", lookup)).toBe("Command and Scripting Interpreter");
  });

  it("returns ParentName: ChildName for sub-techniques", () => {
    const lookup = techniqueLookupFromList([
      technique("T1027", "Obfuscated Files or Information", "defense-evasion"),
      technique("T1027.009", "Embedded Payloads", "defense-evasion", true, "T1027")
    ]);
    expect(techniqueName("T1027.009", lookup)).toBe("Obfuscated Files or Information: Embedded Payloads");
  });

  it("returns child name only when parent name equals parent ID (bad data)", () => {
    const lookup = techniqueLookupFromList([
      technique("T1027", "T1027", "defense-evasion"),       // bad data: name = ID
      technique("T1027.009", "Embedded Payloads", "defense-evasion", true, "T1027")
    ]);
    expect(techniqueName("T1027.009", lookup)).toBe("Embedded Payloads");
  });
});
