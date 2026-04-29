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

export interface TechniqueRef {
  technique_id: string;
  use_description: string | null;
  detected_in_campaigns: string[];
}

export interface ActorDetail {
  id: string;
  name: string;
  aliases: string[];
  description: string | null;
  techniques: TechniqueRef[];
  technique_count: number;
  software_used: SoftwareSummary[];
  software_count: number;
  target_sectors: string[];
  target_countries: string[];
  cves_exploited: string[];
  motivation: string | null;
}

export interface ActorEnrichment {
  target_sectors: string[];
  target_countries: string[];
  cves_exploited: string[];
  motivation: string | null;
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
  rare_shared_techniques: string[];
  explanation: string | null;
  enrichment: ActorEnrichment | null;
}

export interface ActorComparisonResponse {
  input_id: string | null;
  input_name: string;
  input_type: "actor" | "custom_set" | "incident";
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

export interface TTPProfile {
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

export type SavedAnalysisInputType = "actor" | "custom";

export interface AnalysisCreateRequest {
  input_type: SavedAnalysisInputType;
  input_id: string | null;
  input_name: string;
  metric: string;
  tactics?: string[];
  target_ids?: string[];
  top_n: number;
  results: ActorComparisonResponse;
}

export interface AnalysisResponse {
  id: string;
  input_type: SavedAnalysisInputType;
  input_id: string | null;
  input_name: string;
  metric: string;
  tactics: string[] | null;
  target_ids: string[] | null;
  top_n: number;
  created_at: string;
}

export interface AnalysisDetail extends AnalysisResponse {
  results: ActorComparisonResponse;
}

export type PrimarySourceName = "mitre" | "opencti";

export interface MitreSettings {
  auto_update: boolean;
  update_frequency_hours: number;
}

export interface OpenCTISettings {
  url: string | null;
  api_token: string | null;
  auto_update: boolean;
  update_frequency_hours: number;
}

export interface ApplicationSettings {
  active_source: PrimarySourceName;
  mitre: MitreSettings;
  opencti: OpenCTISettings;
}

export interface SourceLoadStatus {
  source: PrimarySourceName;
  status: string;
  version: string | null;
  last_loaded_at: string | null;
  error: string | null;
  actor_count: number;
  campaign_count: number;
  software_count: number;
  technique_count: number;
}

export interface ConnectionTestResult {
  ok: boolean;
  detail: string | null;
}

export interface OpenCTIReport {
  id: string;
  name: string;
  published: string | null;
  description: string | null;
}

export interface ReportTechniquesResponse {
  report_id: string;
  report_name: string;
  technique_ids: string[];
}
