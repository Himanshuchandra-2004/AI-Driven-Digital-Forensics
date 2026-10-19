/** TypeScript interfaces matching backend Pydantic schemas. */

export interface User {
  id: string;
  username: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface Case {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  status: string;
  severity: string | null;
  evidence_count: number;
  threat_count: number;
  anomaly_count: number;
  created_at: string;
  updated_at: string;
  investigator: string | null;
}

export interface AnalysisRun {
  id: string;
  case_id: string;
  status: string;
  source_file: string | null;
  source_type: string;
  total_records: number;
  suspicious_records: number;
  anomaly_count: number;
  threat_count: number;
  preprocessing_time: number | null;
  inference_time: number | null;
  total_time: number | null;
  error_message: string | null;
  metrics: Record<string, any> | null;
  started_at: string;
  completed_at: string | null;
}

export interface ThreatDetection {
  id: string;
  network_event_id: string;
  case_id: string;
  predicted_class: string;
  confidence: number | null;
  class_probabilities: Record<string, number> | null;
  severity: string | null;
  detected_at: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | null;
}

export interface AnomalyDetection {
  id: string;
  network_event_id: string;
  case_id: string;
  anomaly_score: number;
  risk_score: number;
  is_anomaly: boolean;
  severity: string | null;
  detected_at: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | null;
}

export interface Evidence {
  id: string;
  case_id: string;
  evidence_type: string;
  predicted_threat: string | null;
  anomaly_score: number | null;
  classification_confidence: number | null;
  severity: string | null;
  risk_score: number | null;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | null;
  source_file: string | null;
  evidence_hash: string | null;
  previous_hash: string | null;
  status: string;
  extraction_timestamp: string;
  metadata_json: Record<string, any> | null;
}

export interface EvidenceVerification {
  evidence_id: string;
  integrity_verified: boolean;
  stored_hash: string | null;
  calculated_hash: string | null;
  message: string;
}

export interface Incident {
  id: string;
  case_id: string;
  name: string;
  description: string | null;
  severity: string | null;
  risk_score: number | null;
  event_count: number;
  involved_ips: { sources: string[]; destinations: string[] } | null;
  threat_categories: string[] | null;
  first_seen: string | null;
  last_seen: string | null;
  created_at: string;
  evidence_ids: string[] | null;
}

export interface ChainOfCustodyEntry {
  id: string;
  evidence_id: string;
  user_id: string;
  username: string | null;
  action: string;
  description: string | null;
  integrity_hash: string | null;
  timestamp: string;
}

export interface ModelVersion {
  id: string;
  algorithm: string;
  version: string;
  dataset_name: string | null;
  features: string[] | null;
  metrics: Record<string, any> | null;
  parameters: Record<string, any> | null;
  model_path: string | null;
  status: string;
  trained_at: string;
}

export interface DashboardStats {
  total_cases: number;
  active_cases: number;
  total_evidence: number;
  total_threats: number;
  total_anomalies: number;
  critical_incidents: number;
  high_incidents: number;
  threat_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  top_source_ips: { ip: string; count: number }[];
  top_dest_ips: { ip: string; count: number }[];
  recent_cases: Case[];
}

export interface ReportInfo {
  id: string;
  case_id: string;
  user_id: string;
  report_type: string;
  file_path: string | null;
  generated_at: string;
}
