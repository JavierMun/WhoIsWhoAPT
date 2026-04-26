import type {
  ActorComparisonResponse,
  ActorDetail,
  ActorListItem,
  AnalysisCreateRequest,
  AnalysisDetail,
  AnalysisResponse,
  ClusterResponse,
  HealthResponse,
  MatrixResponse,
  SimilarityMetric,
  TechniqueListItem,
  TTPProfile
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

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/api/health");
}

export function getActors(): Promise<ActorListItem[]> {
  return request<ActorListItem[]>("/api/actors");
}

export function getActorDetail(actorId: string): Promise<ActorDetail> {
  return request<ActorDetail>(`/api/actors/${encodeURIComponent(actorId)}`);
}

export function compareActor(
  actorId: string,
  metric: SimilarityMetric,
  topN: number,
  targetIds?: string[],
  tactics?: string[]
): Promise<ActorComparisonResponse> {
  return request<ActorComparisonResponse>("/api/compare/actor", {
    method: "POST",
    body: JSON.stringify({
      actor_id: actorId,
      metric,
      top_n: topN,
      ...(targetIds ? { target_ids: targetIds } : {}),
      ...(tactics && tactics.length > 0 ? { tactics } : {})
    })
  });
}

export function getTechniques(): Promise<TechniqueListItem[]> {
  return request<TechniqueListItem[]>("/api/techniques");
}

export function getTTPProfiles(): Promise<TTPProfile[]> {
  return request<TTPProfile[]>("/api/custom-sets");
}

export function createTTPProfile(name: string, techniqueIds: string[], description?: string): Promise<TTPProfile> {
  return request<TTPProfile>("/api/custom-sets", {
    method: "POST",
    body: JSON.stringify({
      name,
      description,
      technique_ids: techniqueIds
    })
  });
}

export function updateTTPProfile(
  profileId: string,
  name: string,
  techniqueIds: string[],
  description?: string
): Promise<TTPProfile> {
  return request<TTPProfile>(`/api/custom-sets/${encodeURIComponent(profileId)}`, {
    method: "PUT",
    body: JSON.stringify({
      name,
      description,
      technique_ids: techniqueIds
    })
  });
}

export async function deleteTTPProfile(profileId: string): Promise<void> {
  await request<void>(`/api/custom-sets/${encodeURIComponent(profileId)}`, {
    method: "DELETE"
  });
}

export function compareTTPProfile(
  params:
    | { profileId: string; metric: SimilarityMetric; topN: number; tactics?: string[]; targetIds?: string[] }
    | { name: string; techniqueIds: string[]; metric: SimilarityMetric; topN: number; tactics?: string[]; targetIds?: string[] }
): Promise<ActorComparisonResponse> {
  const body =
    "profileId" in params
      ? {
          custom_set_id: params.profileId,
          metric: params.metric,
          top_n: params.topN,
          ...(params.targetIds ? { target_ids: params.targetIds } : {}),
          ...(params.tactics && params.tactics.length > 0 ? { tactics: params.tactics } : {})
        }
      : {
          name: params.name,
          technique_ids: params.techniqueIds,
          metric: params.metric,
          top_n: params.topN,
          ...(params.targetIds ? { target_ids: params.targetIds } : {}),
          ...(params.tactics && params.tactics.length > 0 ? { tactics: params.tactics } : {})
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

export function saveAnalysis(payload: AnalysisCreateRequest): Promise<AnalysisResponse> {
  return request<AnalysisResponse>("/api/analysis/save", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function getAnalyses(): Promise<AnalysisResponse[]> {
  return request<AnalysisResponse[]>("/api/analysis");
}

export function getAnalysisDetail(analysisId: string): Promise<AnalysisDetail> {
  return request<AnalysisDetail>(`/api/analysis/${encodeURIComponent(analysisId)}`);
}

export async function deleteAnalysis(analysisId: string): Promise<void> {
  await request<void>(`/api/analysis/${encodeURIComponent(analysisId)}`, {
    method: "DELETE"
  });
}
