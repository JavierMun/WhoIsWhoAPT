import type { ActorComparisonResponse, ActorListItem, HealthResponse, SimilarityMetric } from "./types";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...init?.headers
    },
    ...init
  });

  if (!response.ok) {
    throw new Error(`Request failed with status ${response.status}`);
  }

  return (await response.json()) as T;
}

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/api/health");
}

export function getActors(): Promise<ActorListItem[]> {
  return request<ActorListItem[]>("/api/actors");
}

export function compareActor(actorId: string, metric: SimilarityMetric, topN: number): Promise<ActorComparisonResponse> {
  return request<ActorComparisonResponse>("/api/compare/actor", {
    method: "POST",
    body: JSON.stringify({
      actor_id: actorId,
      metric,
      top_n: topN
    })
  });
}
