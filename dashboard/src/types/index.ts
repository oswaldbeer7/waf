// Dashboard specific types
export interface Statistics {
  total_requests: number;
  blocked_requests: number;
  allowed_requests: number;
  requests_by_country: Record<string, number>;
}

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
