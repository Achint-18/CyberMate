export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type RiskLevel = 'Low' | 'Moderate' | 'High' | 'Critical';

export interface IndicatorMetadata {
  id: string;
  name: string;
  category: string;
  data_type: 'boolean' | 'number' | 'string';
  default_value: any;
  description: string;
  risk_weight: number;
}

export interface RuleMatchResult {
  rule_id: string;
  rule_name: string;
  category: string;
  threat: string;
  severity: SeverityLevel;
  matched: boolean;
  confidence: number;
  evidence: string[];
  missing_evidence: string[];
  mitre_technique?: string;
  explanation: string;
  recommendations: string[];
}

export interface ThreatDiagnosis {
  threat: string;
  rule_id: string;
  rule_name: string;
  category: string;
  severity: SeverityLevel;
  confidence: number;
  confidence_label: string;
  mitre_technique?: string;
  evidence: string[];
  explanation: string;
  recommendations: string[];
}

export interface RiskBreakdown {
  category: string;
  score: number;
  max_score: number;
  factors: string[];
}

export interface SecurityRiskScore {
  score: number;
  level: RiskLevel;
  description: string;
  contributing_factors: string[];
  category_breakdowns: RiskBreakdown[];
  urgent_actions: string[];
}

export interface DiagnosisReport {
  has_threat: boolean;
  summary: string;
  primary_threat?: ThreatDiagnosis;
  related_threats: ThreatDiagnosis[];
  all_matched_rules: RuleMatchResult[];
  risk_score: SecurityRiskScore;
  overall_recommendations: string[];
  evaluated_facts: Record<string, any>;
  evaluation_metadata: {
    rules_evaluated: number;
    rules_fired: number;
    inference_time_ms: number;
    engine_version: string;
  };
}

export interface IncidentSummary {
  id: string;
  title: string;
  timestamp: string;
  input_method: 'structured' | 'chat' | 'scenario';
  primary_threat: string;
  severity: SeverityLevel;
  confidence: number;
  confidence_label: string;
  risk_score: number;
  risk_level: RiskLevel;
  summary: string;
}

export interface IncidentDetail extends IncidentSummary {
  facts: Record<string, any>;
  report: DiagnosisReport;
}

export interface DashboardMetrics {
  overall_risk_score: number;
  overall_risk_level: RiskLevel;
  incidents_analyzed: number;
  high_critical_count: number;
  threat_library_count: number;
  rules_active_count: number;
  recent_diagnoses: IncidentSummary[];
}

export interface ChatDiagnosisResponse {
  user_query: string;
  extracted_observations: string[];
  extracted_facts: Record<string, any>;
  diagnosis_report: DiagnosisReport;
}

export interface ThreatProfile {
  id: string;
  name: string;
  category: string;
  severity: SeverityLevel;
  mitre_technique?: string;
  summary: string;
  detailed_description: string;
  common_indicators: string[];
  rule_ids: string[];
  defensive_actions: string[];
  detection_strategies: string[];
}

export interface AttackScenario {
  id: string;
  title: string;
  category: string;
  difficulty: 'Beginner' | 'Intermediate' | 'Advanced';
  description: string;
  background_story: string;
  simulated_evidence: string[];
  facts: Record<string, any>;
  expected_threat: string;
  educational_takeaway: string;
}

export interface PasswordGenerateRequest {
  length: number;
  use_uppercase: boolean;
  use_lowercase: boolean;
  use_numbers: boolean;
  use_symbols: boolean;
  exclude_ambiguous: boolean;
}

export interface PasswordGenerateResponse {
  password: string;
  length: number;
  entropy_bits: number;
  strength: 'Weak' | 'Moderate' | 'Strong' | 'Very Strong';
  crack_time_estimate: string;
  security_notice: string;
}

export interface RuleDefinition {
  id: string;
  name: string;
  category: string;
  threat: string;
  severity: SeverityLevel;
  base_confidence: number;
  mitre_technique?: string;
  conditions: Array<{
    field: string;
    operator: string;
    value?: any;
    description?: string;
  }>;
  explanation_template: string;
  recommendations: string[];
}
