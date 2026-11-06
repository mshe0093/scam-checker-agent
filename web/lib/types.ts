export type Severity = "red" | "amber" | "green" | "info";

export interface Signal {
  id: string;
  severity: Severity;
  detail: string;
  deterministic?: boolean;
}

export interface ToolResult {
  tool: string;
  status: "ok" | "unverified" | "error";
  summary: string;
  signals: Signal[];
  evidence: Record<string, unknown>;
  sources: string[];
}

export interface Finding {
  check: string;
  outcome: "fail" | "warn" | "pass" | "unverified";
  detail: string;
}

export interface Verdict {
  verdict: "likely_scam" | "suspicious" | "likely_legitimate" | "insufficient_information";
  confidence: "high" | "medium" | "low";
  category: string;
  headline: string;
  findings: Finding[];
  recommended_actions: string[];
  engine?: string;
  floor_applied?: { from: string; reasons: string[] };
}

export type AgentEvent =
  | { type: "session"; session_id: string; engine?: string }
  | { type: "tool_call"; id: string; name: string; input: Record<string, unknown> }
  | { type: "tool_result"; id: string; name: string; result: ToolResult }
  | { type: "text"; text: string }
  | { type: "verdict"; verdict: Verdict }
  | { type: "error"; message: string }
  | { type: "done"; usage: Record<string, number> };

export interface TraceStep {
  id: string;
  name: string;
  input: Record<string, unknown>;
  result?: ToolResult;
}

export interface Contact {
  label: string;
  value: string;
  verification: string;
  source_url: string;
}
