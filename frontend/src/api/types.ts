export interface HealthResponse {
  status: string;
  service: string;
  environment: string;
  timestamp: string;
}

export type SimilarityMetric =
  | "jaccard"
  | "jaccard_weighted"
  | "tactic_weighted_jaccard"
  | "software_weighted_jaccard";

export interface SoftwareSummary {
  id: string;
  name: string;
  software_type: "malware" | "tool";
}

export interface TacticBreakdown {
  tactic: string;
  shared_techniques: string[];
  input_technique_count: number;
  matched_technique_count: number;
  shared_technique_count: number;
  union_technique_count: number;
  score_contribution: number;
}

export interface ActorListItem {
  id: string;
  name: string;
  aliases: string[];
  technique_count: number;
}

export interface ComparisonResult {
  matched_entity_id: string;
  matched_entity_name: string;
  matched_entity_source: string;
  score: number;
  technique_score: number;
  software_score: number;
  technique_score_contribution: number;
  software_score_contribution: number;
  shared_techniques: string[];
  unique_to_input: string[];
  unique_to_matched_entity: string[];
  shared_software: SoftwareSummary[];
  unique_to_input_software: SoftwareSummary[];
  unique_to_matched_entity_software: SoftwareSummary[];
  tactic_breakdown: TacticBreakdown[];
}

export interface ActorComparisonResponse {
  input_id: string | null;
  input_name: string;
  input_type: "actor" | "custom_set";
  metric: SimilarityMetric;
  results: ComparisonResult[];
}

export interface TechniqueListItem {
  technique_id: string;
  name: string;
  tactic: string;
  is_subtechnique: boolean;
  parent_id: string | null;
}

export interface CustomTTPSet {
  id: string;
  name: string;
  description: string | null;
  technique_ids: string[];
  created_at: string;
  updated_at: string;
}

export interface MatrixMetadata {
  source: string;
  metric: SimilarityMetric;
  generated_at: string;
  actor_count: number;
}

export interface MatrixActor {
  id: string;
  name: string;
  source: string;
}

export interface MatrixResponse {
  metadata: MatrixMetadata;
  actors: MatrixActor[];
  matrix: number[][];
}

export interface ClusterLabel {
  actor_id: string;
  actor_name: string;
  source: string;
  cluster_id: number;
}

export interface ClusterResponse {
  source: string;
  metric: SimilarityMetric;
  generated_at: string;
  actor_count: number;
  cluster_count: number;
  min_similarity: number;
  labels: ClusterLabel[];
}
