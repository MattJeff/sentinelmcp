// Stable contract between the React frontend and the Tauri Rust backend.
// All Tauri commands invoked from the UI must use these types and names.

export type ServerStatus =
  | 'approved'
  | 'unknown'
  | 'suspect'
  | 'to_investigate'
  | 'blocked';

export type SeverityColor = 'green' | 'orange' | 'red';

export type Severity = 'info' | 'medium' | 'high' | 'critical';

export type Transport = 'stdio' | 'http';

export type Scope =
  | 'filesystem'
  | 'database'
  | 'external_api'
  | 'secrets'
  | 'network'
  | 'read'
  | 'write'
  | 'unknown';

export interface ServerCard {
  id: string;
  endpoint: string;
  transport: Transport;
  status: ServerStatus;
  color: SeverityColor;
  scopes: Scope[];
  tool_count: number;
  first_seen: string; // ISO-8601
  last_seen: string;
  current_fingerprint: string | null;
}

export interface Tool {
  name: string;
  description: string | null;
  input_schema: unknown;
}

export interface ServerDetail {
  server: ServerCard;
  tools: Tool[];
  open_findings: number;
}

export interface Finding {
  id: string;
  server_id: string;
  tool_name: string | null;
  finding_type: string;
  severity: Severity;
  title: string;
  detail: string;
  diff: string | null;
  compliance_refs: string[];
  timestamp: string;
  state: 'open' | 'investigating' | 'resolved' | 'ignored';
}

export interface Alert {
  id: string;
  finding_id: string;
  channel: 'dashboard' | 'email' | 'webhook' | 'siem';
  severity: Severity;
  title: string;
  message: string;
  diff: string | null;
  timestamp: string;
}

export interface ScanProgress {
  stage: 'idle' | 'capturing' | 'detecting' | 'finished' | 'error';
  servers_discovered: number;
  tools_discovered: number;
  time_to_first_red_ms: number | null;
  log_line?: string;
}

export interface ExecutiveSummary {
  servers_total: number;
  servers_approved: number;
  servers_unapproved: number;
  servers_at_risk: number;
  findings_critical: number;
  findings_high: number;
  findings_medium: number;
}

export interface ComplianceReference {
  framework: string;
  identifier: string;
  title: string;
  url: string | null;
}

export interface ReportBundle {
  executive_summary_md: string;
  inventory_md: string;
  changelog_md: string;
  compliance_map_md: string;
  remediation_plan_md: string;
  json_path: string | null;
  pdf_path: string | null;
  signed: boolean;
  signature_iso8601: string | null;
}

export interface ApprovalDecision {
  decision: 'approve' | 'investigate' | 'block';
  operator: string;
}

/** Summary of one historical baseline row for a given server. */
export interface BaselineSummary {
  id: string;
  server_id: string;
  fingerprint: string;
  tool_count: number;
  approved_by: string;
  approved_at: string; // ISO-8601
}

// ─── Discovery DTOs ────────────────────────────────────────────────────────
// Surfaced by the Discovery page: read every known AI-client config file on
// the user's Mac and list the MCP servers it declares.

export type DiscoveredClientKind =
  | 'claude-desktop'
  | 'claude-code-cli'
  | 'cursor'
  | 'windsurf'
  | 'zed'
  | 'vscode'
  | 'continue'
  | 'aider'
  | 'goose'
  | 'codex'
  | 'antigravity'
  | 'lm-studio';

export interface DeclaredServer {
  name: string;
  transport: Transport;
  /** npm package or binary identifier — e.g. `@modelcontextprotocol/server-filesystem`. */
  package: string | null;
  scopes: Scope[];
  /** Stdio binary to spawn (when known); required to launch a live probe. */
  command?: string | null;
  /** Stdio arguments; empty when not applicable. */
  args?: string[];
}

export type ProbeState =
  | 'success'
  | 'launch_failed'
  | 'handshake_failed'
  | 'parse_failed';

export interface ProbeTool {
  name: string;
  description: string | null;
}

export interface ProbePoisoningFinding {
  pattern: string;
  category: string;
  excerpt: string;
  severity: string;
}

export interface ProbeResult {
  server_name: string;
  state: ProbeState;
  tool_count: number;
  fingerprint: string | null;
  tools: ProbeTool[];
  poisoning_findings: ProbePoisoningFinding[];
  duration_ms: number;
  error: string | null;
  /** @deprecated Derived from `state === 'success'`. Kept for back-compat. */
  reachable?: boolean;
  /** @deprecated Use `duration_ms` instead. */
  latency_ms?: number | null;
}

export interface ThreatMatch {
  server_name: string;
  rule_id: string;
  severity: Severity;
  title: string;
  detail: string;
}

export interface SupplyChainAttestation {
  package: string;
  publisher: string | null;
  signed: boolean;
  sigstore_url: string | null;
  last_release_iso8601: string | null;
}

export interface TrustGraphEdge {
  from: string;
  to: string;
  weight: number;
}

export interface TrustGraph {
  nodes: { id: string; label: string; kind: 'client' | 'server' | 'package' }[];
  edges: TrustGraphEdge[];
}

// ─── Computed trust graph (compute_trust_graph) ────────────────────────────
// Returned by the Rust `ConstructeurGraphe`: real blast-radius per client
// plus inferred scopes per server, so the UI doesn't recompute anything.

export interface TrustGraphNode {
  id: string;
  label: string;
  kind: 'client' | 'server';
  /** Blast-radius score; only present for `kind === 'client'`. */
  blast_radius: number | null;
  /** Inferred functional scopes; only populated on server nodes. */
  scopes: string[];
}

export interface TrustGraphComputedEdge {
  from: string;
  to: string;
}

export interface TrustGraphComputed {
  nodes: TrustGraphNode[];
  edges: TrustGraphComputedEdge[];
  /** Max blast radius observed; UI normalises bars against this. */
  max_blast_radius: number;
}

// ─── Threat intelligence feed (list_threats) ───────────────────────────────
// One entry of the bundled `FluxMenaces` feed, enriched with how many MCP
// servers currently declared on this Mac match the threat package.

export interface ThreatEntry {
  identifier: string;
  package_name: string;
  reason: string;
  /** "critical" | "high" | "medium" — typed loosely to mirror the YAML feed. */
  severity: string;
  references: string[];
  /** ISO date (YYYY-MM-DD) the entry was published in the feed. */
  published_at: string;
  /** Number of currently-declared MCP servers matching this threat. */
  matches_count: number;
}

export interface DiscoveredClient {
  kind: DiscoveredClientKind;
  label: string;
  version: string | null;
  installed: boolean;
  /** Tilde-expanded paths Sentinel inspected. */
  configs: string[];
  servers: DeclaredServer[];
  notes: string[];
}

export interface DiscoveryReport {
  clients: DiscoveredClient[];
  probes?: ProbeResult[];
  threats?: ThreatMatch[];
  attestations?: SupplyChainAttestation[];
  trust_graph?: TrustGraph | null;
}

// ─── Observed JSON-RPC events (Time-travel page) ───────────────────────────
// Every JSON-RPC envelope Sentinel has captured on the wire, replayable
// after the fact by an auditor.

export type ObservedDirection = 'client_to_server' | 'server_to_client';

export interface ObservedEvent {
  id: string;
  server_id: string;
  server_endpoint: string;
  session_id: string;
  direction: ObservedDirection;
  method: string;
  jsonrpc_id: string | number | null;
  timestamp: string; // ISO-8601
  envelope: Record<string, unknown>;
}

export interface ObservedEventFilter {
  server_id?: string;
  method?: string;
  direction?: ObservedDirection;
  since?: string; // ISO-8601
  until?: string; // ISO-8601
}

// ─── Settings DTO (mirrors src-tauri/src/commands_settings.rs) ─────────────

export interface SettingsCapture {
  default_mode: 'fixture' | 'stdio' | 'http';
  http_port: number;
}

export interface SettingsEmail {
  enabled: boolean;
  host: string;
  port: number;
  from: string;
  to: string;
}

export interface SettingsWebhook {
  enabled: boolean;
  url: string;
  format: 'generic' | 'slack' | 'teams';
}

export interface SettingsAlerts {
  email: SettingsEmail;
  webhook: SettingsWebhook;
}

export interface SettingsRetention {
  contacts_days: number;
  findings_days: number;
  alerts_days: number;
}

export interface SettingsPrivacy {
  in_flight_only: boolean;
  outbound_lookups: boolean;
}

export interface Settings {
  capture: SettingsCapture;
  alerts: SettingsAlerts;
  retention: SettingsRetention;
  privacy: SettingsPrivacy;
}

// ─── Test email channel DTOs ───────────────────────────────────────────────

export interface TestEmailInput {
  smtp_host: string;
  smtp_port: number;
  user: string | null;
  password: string | null;
  sender: string;
  recipient: string;
}

export interface TestEmailResult {
  ok: boolean;
  file_path: string | null;
  error: string | null;
}

// ─── Test webhook channel DTOs ─────────────────────────────────────────────

export interface TestWebhookInput {
  url: string;
  format: 'generic' | 'slack' | 'teams';
}

export interface TestWebhookResult {
  ok: boolean;
  status: number | null;
  body_preview: string | null;
  error: string | null;
}

// ─── Live background monitoring (get_live_status / set_live_interval) ─────

/** Snapshot of the live background loop, returned by `get_live_status`. */
export interface LiveStatus {
  /** Current tick interval (seconds) between two automatic sweeps. */
  interval_secs: number;
  /** ISO-8601 timestamp of the most recent background scan. */
  last_refresh_iso: string;
  /** Absolute paths the filesystem watcher is armed on. */
  watching_paths: string[];
}

/** Payload of the `sentinel://live-tick` event. */
export interface LiveTick {
  last_refresh_iso: string;
  servers_total: number;
  findings_total: number;
}

// Tauri command names — must match exactly the #[tauri::command] functions.
export const COMMANDS = {
  listServers: 'list_servers',
  getServerDetail: 'get_server_detail',
  startScan: 'start_scan',
  stopScan: 'stop_scan',
  scanProgress: 'scan_progress',
  listFindings: 'list_findings',
  listAlerts: 'list_alerts',
  applyApproval: 'apply_approval',
  listBaselines: 'list_baselines',
  generateReport: 'generate_report',
  openReportFile: 'open_report_file',
  executiveSummary: 'executive_summary',
  complianceReferences: 'compliance_references',
  appVersion: 'app_version',
  discoverSystem: 'discover_system',
  computeTrustGraph: 'compute_trust_graph',
  listThreats: 'list_threats',
  probeServer: 'probe_server',
  listObservedEvents: 'list_observed_events',
  getSettings: 'get_settings',
  saveSettings: 'save_settings',
  testEmailChannel: 'test_email_channel',
  testWebhookChannel: 'test_webhook_channel',
  getLiveStatus: 'get_live_status',
  setLiveInterval: 'set_live_interval',
} as const;

// Tauri events broadcast from backend to frontend.
export const EVENTS = {
  scanProgress: 'sentinel://scan-progress',
  newAlert: 'sentinel://alert',
  newServer: 'sentinel://server-discovered',
  liveTick: 'sentinel://live-tick',
} as const;
