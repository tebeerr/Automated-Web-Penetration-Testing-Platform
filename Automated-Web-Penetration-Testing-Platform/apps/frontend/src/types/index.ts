export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type ScanStatus =
  | 'pending'
  | 'validating'
  | 'recon'
  | 'scanning'
  | 'ai_analyzing'
  | 'generating_report'
  | 'completed'
  | 'failed'
  | 'cancelled'

export interface Scan {
  id: string
  user_id: string
  target_url: string
  status: ScanStatus
  scan_profile: string
  progress: number
  current_phase: string | null
  start_time: string | null
  end_time: string | null
  error_message: string | null
  created_at: string
}

export interface Vulnerability {
  id: string
  scan_id: string
  owasp_category: string
  owasp_name: string
  name: string
  description: string
  severity: Severity
  cvss_score: number | null
  cwe_id: string | null
  evidence: string | null
  payload: string | null
  url_affected: string | null
  parameter: string | null
  remediation: string | null
  ai_confidence: number
  ai_narrative: string | null
  source_scanner: string | null
  is_false_positive: boolean
  created_at: string
}

export interface Report {
  id: string
  scan_id: string
  report_type: 'full' | 'executive' | 'technical'
  file_path: string | null
  file_size_kb: number | null
  generated_at: string
  ai_summary: string | null
}

export interface VerifiedTarget {
  id: string
  user_id: string
  domain: string
  verification: 'dns_txt' | 'meta_tag' | 'file_upload'
  verified_at: string
  expires_at: string | null
}

export type PageId = 'dashboard' | 'scan' | 'history' | 'reports' | 'settings'
