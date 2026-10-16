/**
 * OpenAPI 3.1 Data Contracts for Supply Chain Guardian (SCG) Frontend.
 *
 * Conforms to IEEE Std 830-1998, RFC 2119, and SCG-SRS-PHASE-8 (REQ-P8-01).
 * Strictly mirrors backend schemas without client-side score recalculations.
 */

export type RiskTier = "CRITICAL" | "HIGH" | "MODERATE" | "LOW" | "CLEAN";

export type ReachabilityStatus =
  | "DIRECT_IMPORTED"
  | "UNKNOWN_REACHABILITY"
  | "TRANSITIVE_REQUIRED"
  | "UNREFERENCED_LATENT"
  | "DEV_DEPENDENCY";

export interface GraphNodeSummary extends Record<string, unknown> {
  purl: string;
  package_name: string;
  version: string;
  depth: number | null;
  composite_score: number;
  risk_tier: RiskTier;
  risk_reason: string;
  should_emphasize: boolean;
  vuln_count: number;
  reachability: ReachabilityStatus;
  x_coord?: number;
  y_coord?: number;
  is_aggregate_cluster?: boolean;
  aggregated_count?: number;
}

export interface GraphEdge {
  source: string;
  target: string;
}

export interface BoundedGraphResponse {
  scan_id: string;
  total_nodes: number;
  truncated: boolean;
  nodes: GraphNodeSummary[];
  edges: GraphEdge[];
}
