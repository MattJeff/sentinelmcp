# V20 — Final Workspace Smoke Test Report

Date: 2026-06-02

## Build Status

| Stage              | Status | Notes                                                                         |
| ------------------ | ------ | ----------------------------------------------------------------------------- |
| `cargo build --workspace` | GREEN  | Finished in 3.94s. No fixes required. All 9 crates compile cleanly.    |
| `pnpm build` (tsc + vite) | GREEN  | tsc --noEmit clean. Vite built 1875 modules in 781ms. No fixes required. |
| `cargo test --workspace --no-fail-fast` | GREEN  | **487 passed, 0 failed, 10 ignored** across all crates + doc-tests. |

No compile fixes were needed. V1–V19 landed cleanly.

## Workspace Layout

- Rust workspace: 9 crates under `crates/` (alerts, cli, detect, discovery, monitor, protocol, report, scan, store) plus `sentinel-desktop/src-tauri`.
- Frontend: React+TS in `sentinel-desktop/src` (53 .ts/.tsx files), Vite 8.

## V1–V19 Feature Wiring — Confirmed

### Tauri commands (in `src-tauri/src/commands*.rs`)

Discovery / scan / inventory:
- `start_scan`, `stop_scan`, `scan_progress`, `list_servers`, `get_server_detail`, `probe_server`
- `discover_system` (commands_discovery.rs)
- `get_live_status`, `set_live_interval`, `list_observed_events`

Detection / threats:
- `list_findings`, `list_threats`, `list_baselines`, `resolve_finding`
- `scan_lookalikes` (commands_lookalikes.rs), `compute_trust_graph`

Alerts / approvals / investigations:
- `list_alerts`, `apply_approval`, `create_investigation`, `list_investigations`
- `test_email_channel`, `test_webhook_channel`

Enforcement / proxy:
- `enforcement_remove_server`, `enforcement_restore` (commands_enforcement.rs)
- `start_proxy`, `stop_proxy`, `proxy_status` (commands_proxy.rs)

Reporting / compliance / settings / SIEM:
- `generate_report`, `open_report_file`, `executive_summary`, `compliance_references`
- `get_settings`, `save_settings`
- `siem_get_config`, `siem_save_config`, `siem_test_send`

### Frontend pages wired

OverviewPage, ScanPage, InventoryPage, DiscoveryPage, AlertsPage, ApprovalsPage, TimelinePage, TrustGraphPage, CompliancePage, ReportPage, SettingsPage — plus charts, graph canvas, command palette, enforcement dialogs, lookalike/threat panels, authorization gate, investigation dialog, live log, diff viewer.

## Conclusion

Workspace is fully green: builds, type-checks, tests. Ready for packaging.
