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

/**
 * Visibility scope of a declared MCP server: either tied to the current
 * macOS user (the default) or scoped to a specific project on disk. The
 * tagged-union shape matches the Rust wire DTO emitted by `commands.rs`
 * and is treated as optional on the TypeScript side so older payloads
 * (where the field is absent) still deserialise cleanly.
 */
export type ScopeServeur =
  | { kind: 'user' }
  | { kind: 'project'; path: string };

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
  /**
   * Operator-curated free-form tags persisted on the server row (e.g.
   * `prod`, `internal`, `customer-x`). Optional because older backends may
   * not yet expose the field; treat `undefined` as an empty array.
   */
  tags?: string[];
  /**
   * Visibility scope: either `{ kind: 'user' }` (declared globally for the
   * macOS user) or `{ kind: 'project', path }` (declared inside a specific
   * project tree). Optional — treat `undefined` as `{ kind: 'user' }` for
   * back-compat with older Rust builds that don't emit the field yet.
   */
  scope?: ScopeServeur;
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

/** Payload for the `resolve_finding` command — marks a finding as resolved. */
export interface ResolveFindingInput {
  finding_id: string;
  note: string | null;
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

/** Parameters accepted by `start_scan`. */
export interface ScanParams {
  mode?: 'stdio' | 'http';
  /** Required when `mode === 'http'`: the Streamable HTTP MCP endpoint to probe. */
  httpUrl?: string | null;
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

// ─── Lookalike scan (scan_lookalikes) ─────────────────────────────────────
// One row returned by the registry-backed brand-similarity sweep. A match
// means a registry entry whose name/description is suspiciously close to
// one of the user's own declared servers but is NOT the exact same
// identifier (i.e. a likely typo-squat / doppelganger).

/** Per-signal contribution to the combined similarity score. */
export interface LookalikeScoreBreakdown {
  /** Jaro-Winkler on the names. */
  name: number;
  /** Jaccard on description tokens. */
  description: number;
  /** Jaccard on tool names. */
  tools: number;
  /** Jaccard on the union of declared enum values. */
  enums: number;
}

export interface LookalikeMatch {
  /** "registry" (public registry match) or "intra-inventory" (pair of declared servers). */
  source?: string;
  /** UUID of the declared server in the local inventory, when known. */
  declared_id?: string | null;
  /** Declared package on this Mac (server name). */
  declared_package: string;
  /** Short id of the registry where the candidate was found, or "intra" for intra-inventory pairs. */
  registry: string;
  /** Candidate name as published in the registry, or name of the other declared server. */
  candidate_name: string;
  /** Candidate description as published in the registry. Empty for intra-inventory pairs. */
  candidate_description: string;
  /** Combined similarity score in [0.0 ; 1.0]. */
  similarity_score: number;
  /** "critical" | "high" | "medium". */
  severity: string;
  /** Signals that individually crossed the 0.7 confidence threshold
   *  ("name", "description", "tool-overlap", "enum-overlap"). */
  signals?: string[];
  /** Per-signal score breakdown so the UI can render a sparkbar. */
  score_breakdown?: LookalikeScoreBreakdown;
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
  /** SMTP auth user (empty string = no auth). */
  user: string;
  /**
   * SMTP auth password. The backend never returns the clear secret: when a
   * password is stored (OS keyring), `get_settings` returns the `"********"`
   * sentinel. Sending the sentinel back unchanged on save keeps the existing
   * secret; sending an empty string clears it.
   */
  pass: string;
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

/**
 * Optional enforcement mode added by V8.
 * When `enabled` is true, the Block action in the Approvals queue and the
 * ServerDetailDrawer footer triggers a real removal of the server from the
 * declaring AI-client config file, with a timestamped backup written next
 * to it. OFF by default — Sentinel stays read-only until the operator
 * explicitly opts in.
 */
export interface SettingsEnforcement {
  enabled: boolean;
}

/**
 * General/UX-level preferences (V0.4). Currently houses the tray-mode
 * toggle: when `keep_running_in_background` is true (default), closing the
 * main window hides Sentinel to the macOS menu bar rather than quitting.
 */
export interface SettingsGeneral {
  keep_running_in_background: boolean;
}

/**
 * Threat-intel feed refresh preferences (V0.3). Mirrors the
 * `ThreatFeedSettings` block on the Rust side. Defaults to enabled with
 * the public GitHub URL; the cascade in
 * `sentinel_discovery::threat_intel::refresh::charger_feed` transparently
 * falls back to the disk cache or the bundled YAML if the remote URL is
 * unreachable.
 */
export interface SettingsThreatFeed {
  url: string;
  auto_refresh_enabled: boolean;
  /** ISO-8601 timestamp of the last successful refresh, stamped by `threat_feed_refresh`. */
  last_refresh_at: string | null;
}

export interface Settings {
  capture: SettingsCapture;
  alerts: SettingsAlerts;
  retention: SettingsRetention;
  privacy: SettingsPrivacy;
  enforcement: SettingsEnforcement;
  general: SettingsGeneral;
  threat_feed: SettingsThreatFeed;
}

/**
 * UI-facing status returned by `threat_feed_status` /
 * `threat_feed_refresh`. The `source` field documents which leg of the
 * cascade produced the active feed (`remote`, `cache`, `bundled`); the
 * `age_seconds` field is the number of seconds since `last_refresh`.
 */
export interface ThreatFeedStatus {
  source: 'remote' | 'cache' | 'bundled' | string;
  last_refresh: string | null;
  age_seconds: number | null;
  entries_count: number;
  version: string | null;
  url: string;
  auto_refresh_enabled: boolean;
}

// ─── Enforcement DTOs (mirrors src-tauri/src/commands_enforcement.rs) ──────

/**
 * Outcome of an enforcement removal — emitted by `enforcement_remove_server`.
 * `config_path` is the AI-client config file Sentinel rewrote; `backup_path`
 * is the absolute path of the timestamped backup written next to it.
 */
export interface EnforcementRemoveResult {
  ok: boolean;
  server_id: string;
  /** Client whose config was edited. */
  client_kind: DiscoveredClientKind | null;
  /** Absolute path of the config file that was rewritten. */
  config_path: string;
  /** Absolute path of the backup written next to the config. */
  backup_path: string;
  /** Populated when `ok === false`. */
  error: string | null;
}

/**
 * Outcome of an enforcement restore — emitted by `enforcement_restore`.
 * Re-inserts the previously removed declaration from the backup file and
 * returns the same paths so the UI can confirm the round-trip.
 */
export interface EnforcementRestoreResult {
  ok: boolean;
  config_path: string;
  backup_path: string;
  error: string | null;
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

// ─── Investigations (create_investigation / list_investigations) ──────────
// An investigation is a persisted free-form note attached to a server, opened
// from the "Investigate" action. Surfaced in the audit trail.

export interface Investigation {
  id: string;
  server_id: string;
  note: string;
  created_by: string;
  /**
   * Mirror of `created_by` exposed for compatibility with UI components
   * written against the legacy "operator" shape. Populated by the TS wrapper.
   */
  operator: string;
  created_at: string; // ISO-8601
  state: string; // 'ouvert' by default
}

// ─── SIEM sink configuration (siem_test_send / siem_save_config /
//     siem_get_config / siem_pick_ca_pem) — mirrors
//     src-tauri/src/commands_siem.rs.
//
// Three backends are supported. `kind` selects which fields are required:
//   * `"splunk"`  — `url` (HEC URL) + `token`.
//   * `"elastic"` — `url` (cluster base URL) + `index`; optional Basic
//     auth via `user` + `pass`.
//   * `"syslog"`  — `addr` (`host:port`). The wire transport is selected
//     by `transport` (`"udp"` default | `"tcp"` | `"tls"`); when `"tls"`
//     is selected, `tls_ca_pem_path` may point at a local PEM bundle for
//     custom trust (system store used when empty).
// Unused fields may be `null` or omitted. Configs persisted before the
// transport selector landed parse cleanly and default to UDP.

export type SiemKind = 'splunk' | 'elastic' | 'syslog';

export type SyslogTransport = 'udp' | 'tcp' | 'tls';

export interface SiemConfig {
  kind: SiemKind | string;
  url?: string | null;
  token?: string | null;
  index?: string | null;
  user?: string | null;
  pass?: string | null;
  addr?: string | null;
  /** `"udp"` (default) | `"tcp"` | `"tls"`. Absent / null => UDP. */
  transport?: SyslogTransport | string | null;
  /** Absolute path to a custom CA PEM bundle (TLS transport only). */
  tls_ca_pem_path?: string | null;
}

// ─── Active MCP proxy (start_proxy / stop_proxy / proxy_status) ───────────
// Snapshot of the local mode-B proxy task (sentinel_scan::http::proxy::ProxyMcp).
// `port` and `upstream` are null while the proxy is idle.

export interface ProxyStatus {
  running: boolean;
  port: number | null;
  upstream: string | null;
  events_seen: number;
}

// Tauri command names — must match exactly the #[tauri::command] functions.
export const COMMANDS = {
  listServers: 'list_servers',
  getServerDetail: 'get_server_detail',
  startScan: 'start_scan',
  stopScan: 'stop_scan',
  scanProgress: 'scan_progress',
  listFindings: 'list_findings',
  resolveFinding: 'resolve_finding',
  listAlerts: 'list_alerts',
  applyApproval: 'apply_approval',
  listBaselines: 'list_baselines',
  generateReport: 'generate_report',
  openReportFile: 'open_report_file',
  stixExportBundle: 'stix_export_bundle',
  executiveSummary: 'executive_summary',
  complianceReferences: 'compliance_references',
  appVersion: 'app_version',
  discoverSystem: 'discover_system',
  computeTrustGraph: 'compute_trust_graph',
  listThreats: 'list_threats',
  scanLookalikes: 'scan_lookalikes',
  probeServer: 'probe_server',
  listObservedEvents: 'list_observed_events',
  getSettings: 'get_settings',
  saveSettings: 'save_settings',
  testEmailChannel: 'test_email_channel',
  testWebhookChannel: 'test_webhook_channel',
  getLiveStatus: 'get_live_status',
  setLiveInterval: 'set_live_interval',
  createInvestigation: 'create_investigation',
  listInvestigations: 'list_investigations',
  enforcementRemoveServer: 'enforcement_remove_server',
  enforcementRestore: 'enforcement_restore',
  startProxy: 'start_proxy',
  stopProxy: 'stop_proxy',
  proxyStatus: 'proxy_status',
  siemTestSend: 'siem_test_send',
  siemSaveConfig: 'siem_save_config',
  siemGetConfig: 'siem_get_config',
  siemPickCaPem: 'siem_pick_ca_pem',
  serverSetTags: 'server_set_tags',
  serverListTags: 'server_list_tags',
  threatFeedRefresh: 'threat_feed_refresh',
  threatFeedStatus: 'threat_feed_status',
} as const;

// Tauri events broadcast from backend to frontend.
export const EVENTS = {
  scanProgress: 'sentinel://scan-progress',
  newAlert: 'sentinel://alert',
  newServer: 'sentinel://server-discovered',
  liveTick: 'sentinel://live-tick',
  threatFeedRefreshed: 'sentinel://threat-feed-refreshed',
} as const;
