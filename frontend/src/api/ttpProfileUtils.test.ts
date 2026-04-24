import { describe, expect, it } from "vitest";

import {
  extractNavigatorTechniqueIds,
  groupTechniquesByTactic,
  normalizeTechniqueIds,
  parseTechniqueIds,
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
});

function technique(technique_id: string, name: string, tactic: string): TechniqueListItem {
  return {
    technique_id,
    name,
    tactic,
    is_subtechnique: false,
    parent_id: null
  };
}
