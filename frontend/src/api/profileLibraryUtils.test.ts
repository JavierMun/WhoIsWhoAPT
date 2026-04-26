import { describe, expect, it } from "vitest";

import {
  buildComparableProfiles,
  filterComparableProfiles,
  groupComparableProfiles,
  parseProfileKey,
  profileDetail,
  profileKey
} from "./profileLibraryUtils";
import type { ActorListItem, TTPProfile } from "./types";

describe("profile library utilities", () => {
  it("builds comparable profiles with custom profiles first", () => {
    const profiles = buildComparableProfiles([actor("a1", "APT Alpha")], [custom("c1", "Imported Layer")]);

    expect(profiles.map((profile) => profile.key)).toEqual(["custom:c1", "actor:a1"]);
  });

  it("groups custom profiles before actor profiles", () => {
    const groups = groupComparableProfiles([actorProfile("a1", "APT Alpha"), customProfile("c1", "Imported Layer")]);

    expect(groups.map((group) => group.label)).toEqual(["Custom TTP Profiles", "Actor Profiles"]);
    expect(groups[0].options.map((profile) => profile.key)).toEqual(["custom:c1"]);
    expect(groups[1].options.map((profile) => profile.key)).toEqual(["actor:a1"]);
  });

  it("filters profiles by name, alias, or type", () => {
    const profiles = buildComparableProfiles([actor("a1", "APT Alpha", ["Hidden Lynx"])], [custom("c1", "Imported Layer")]);

    expect(filterComparableProfiles(profiles, "lynx").map((profile) => profile.key)).toEqual(["actor:a1"]);
    expect(filterComparableProfiles(profiles, "custom").map((profile) => profile.key)).toEqual(["custom:c1"]);
  });

  it("parses stable profile keys", () => {
    expect(profileKey("actor", "abc")).toBe("actor:abc");
    expect(parseProfileKey("custom:c1")).toEqual({ type: "custom", id: "c1" });
    expect(parseProfileKey("bad")).toBeNull();
  });

  it("describes profile options without calling custom profiles actors", () => {
    expect(profileDetail(customProfile("c1", "Imported Layer"))).toBe("Custom TTP Profile - 2 techniques");
    expect(profileDetail(actorProfile("a1", "APT Alpha"))).toBe("Actor Profile - 4 techniques");
  });
});

function actor(id: string, name: string, aliases: string[] = []): ActorListItem {
  return { id, name, aliases, technique_count: 4 };
}

function custom(id: string, name: string): TTPProfile {
  return {
    id,
    name,
    description: null,
    technique_ids: ["T1059", "T1105"],
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z"
  };
}

function actorProfile(id: string, name: string) {
  return buildComparableProfiles([actor(id, name)], [])[0];
}

function customProfile(id: string, name: string) {
  return buildComparableProfiles([], [custom(id, name)])[0];
}
