export interface HealthResponse {
  status: string;
  service: string;
  environment: string;
  timestamp: string;
}

export type SimilarityMetric = "jaccard" | "jaccard_weighted";

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
  shared_techniques: string[];
  unique_to_input: string[];
  unique_to_matched_entity: string[];
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
