import type { ActorDetail, ActorListItem, TTPProfile } from "./types";

export type ComparableProfileType = "actor" | "custom";

export type ComparableProfile = {
  id: string;
  key: string;
  name: string;
  type: ComparableProfileType;
  description?: string | null;
  aliases?: string[];
  technique_ids?: string[];
  technique_count: number;
};

export type ProfileOptionGroup = {
  label: string;
  options: ComparableProfile[];
};

export function actorToComparableProfile(actor: ActorListItem | ActorDetail): ComparableProfile {
  return {
    id: actor.id,
    key: profileKey("actor", actor.id),
    name: actor.name,
    type: "actor",
    aliases: actor.aliases,
    description: "description" in actor ? actor.description : undefined,
    technique_ids: "techniques" in actor ? actor.techniques.map((technique) => technique.technique_id) : undefined,
    technique_count: actor.technique_count
  };
}

export function customToComparableProfile(profile: TTPProfile): ComparableProfile {
  return {
    id: profile.id,
    key: profileKey("custom", profile.id),
    name: profile.name,
    type: "custom",
    description: profile.description,
    technique_ids: profile.technique_ids,
    technique_count: profile.technique_ids.length
  };
}

export function buildComparableProfiles(actors: ActorListItem[], customProfiles: TTPProfile[]): ComparableProfile[] {
  return [
    ...customProfiles.map((profile) => customToComparableProfile(profile)),
    ...actors.map((actor) => actorToComparableProfile(actor))
  ];
}

export function groupComparableProfiles(profiles: ComparableProfile[]): ProfileOptionGroup[] {
  return [
    {
      label: "Custom TTP Profiles",
      options: profiles.filter((profile) => profile.type === "custom")
    },
    {
      label: "Actor Profiles",
      options: profiles.filter((profile) => profile.type === "actor")
    }
  ];
}

export function profileKey(type: ComparableProfileType, id: string): string {
  return `${type}:${id}`;
}

export function parseProfileKey(key: string): { type: ComparableProfileType; id: string } | null {
  const [type, ...idParts] = key.split(":");
  const id = idParts.join(":");
  if ((type === "actor" || type === "custom") && id) {
    return { type, id };
  }
  return null;
}

export function filterComparableProfiles(profiles: ComparableProfile[], query: string): ComparableProfile[] {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    return profiles;
  }

  return profiles.filter((profile) => {
    const aliases = profile.aliases?.join(" ").toLowerCase() ?? "";
    return (
      profile.name.toLowerCase().includes(normalizedQuery) ||
      aliases.includes(normalizedQuery) ||
      profile.type.toLowerCase().includes(normalizedQuery)
    );
  });
}

export function profileTypeLabel(type: ComparableProfileType): string {
  return type === "actor" ? "Actor Profile" : "Custom TTP Profile";
}

export function profileDetail(profile: ComparableProfile): string {
  return `${profileTypeLabel(profile.type)} - ${profile.technique_count} techniques`;
}

export function profileTechniqueIds(profile: ComparableProfile, actorDetail?: ActorDetail | null): string[] {
  if (profile.type === "actor") {
    return actorDetail?.techniques.map((technique) => technique.technique_id) ?? profile.technique_ids ?? [];
  }
  return profile.technique_ids ?? [];
}
