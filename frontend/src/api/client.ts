import type {
  ActorComparisonResponse,
  ActorListItem,
  ClusterResponse,
  CustomTTPSet,
  HealthResponse,
  MatrixResponse,
  SimilarityMetric,
  TechniqueListItem
} from "./types";

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
    let message = `Request failed with status ${response.status}`;
    try {
      const errorBody = (await response.json()) as { error?: string; detail?: unknown };
      if (errorBody.error) {
        message = errorBody.error;
      }
      if (errorBody.detail && typeof errorBody.detail === "object" && "technique_ids" in errorBody.detail) {
        const detail = errorBody.detail as { technique_ids?: string[] };
        message = `${message}: ${(detail.technique_ids ?? []).join(", ")}`;
      }
    } catch {
      // Keep the HTTP status fallback if the backend does not return JSON.
    }
    throw new Error(message);
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

export function getTechniques(): Promise<TechniqueListItem[]> {
  return request<TechniqueListItem[]>("/api/techniques");
}

export function getCustomSets(): Promise<CustomTTPSet[]> {
  return request<CustomTTPSet[]>("/api/custom-sets");
}

export function createCustomSet(name: string, techniqueIds: string[]): Promise<CustomTTPSet> {
  return request<CustomTTPSet>("/api/custom-sets", {
    method: "POST",
    body: JSON.stringify({
      name,
      technique_ids: techniqueIds
    })
  });
}

export function compareCustomSet(
  params:
    | { customSetId: string; metric: SimilarityMetric; topN: number }
    | { name: string; techniqueIds: string[]; metric: SimilarityMetric; topN: number }
): Promise<ActorComparisonResponse> {
  const body =
    "customSetId" in params
      ? {
          custom_set_id: params.customSetId,
          metric: params.metric,
          top_n: params.topN
        }
      : {
          name: params.name,
          technique_ids: params.techniqueIds,
          metric: params.metric,
          top_n: params.topN
        };

  return request<ActorComparisonResponse>("/api/compare/custom", {
    method: "POST",
    body: JSON.stringify(body)
  });
}

export function computeMatrix(metric: SimilarityMetric): Promise<MatrixResponse> {
  return request<MatrixResponse>("/api/matrix", {
    method: "POST",
    body: JSON.stringify({ metric })
  });
}

export function getMatrixResult(): Promise<MatrixResponse> {
  return request<MatrixResponse>("/api/matrix/result");
}

export function getClusters(minSimilarity = 0.15): Promise<ClusterResponse> {
  return request<ClusterResponse>(`/api/clusters?min_similarity=${encodeURIComponent(minSimilarity)}`);
}
