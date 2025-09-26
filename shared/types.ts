// Shared types between backend and frontend

export interface Domain {
  id: number;
  name: string;
  origin_url: string;
  created_at: string;
}

export interface RequestLog {
  id: number;
  domain_id: number;
  ip: string;
  path: string;
  user_agent: string;
  country: string;
  isp: string;
  org: string;
  asn: string;
  user_type: string;
  decision: string;
  timestamp: string;
}

export interface BotRule {
  id: number;
  domain_id: number;
  type: "allow" | "deny";
  field: "country" | "asn" | "isp" | "user_type";
  value: string;
}

export interface IPInfo {
  ip: string;
  country: string;
  isp: string;
  org: string;
  asn: string;
  user_type: string;
}

export interface Statistics {
  total_requests: number;
  blocked_requests: number;
  allowed_requests: number;
  requests_by_country: Record<string, number>;
}

export interface ApiResponse<T> {
  data?: T;
  error?: string;
  message?: string;
}

export interface DomainStats extends Statistics {
  domain_name: string;
}

export interface CreateDomainRequest {
  name: string;
  origin_url: string;
}

export interface CreateBotRuleRequest {
  domain_id: number;
  type: "allow" | "deny";
  field: "country" | "asn" | "isp" | "user_type";
  value: string;
}

export interface UpdateBotRuleRequest {
  domain_id: number;
  type: "allow" | "deny";
  field: "country" | "asn" | "isp" | "user_type";
  value: string;
}
