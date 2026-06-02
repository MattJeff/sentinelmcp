// System-Preferences-style settings page.
// Hydrates from the backend (TOML on disk) via `get_settings` and persists
// every change through `save_settings`. Live monitoring interval is a
// runtime knob set through `set_live_interval`.

import { useEffect, useMemo, useRef, useState } from 'react';
import useSWR, { mutate as globalMutate } from 'swr';
import { create } from 'zustand';
import clsx from 'clsx';
import { AlertTriangle, Info, Lock, ShieldCheck } from 'lucide-react';
import { invoke } from '@tauri-apps/api/core';

import { api } from '../api/tauri';
import {
  COMMANDS,
  type ComplianceReference,
  type LiveStatus,
  type Settings as PersistedSettings,
} from '../api/contract';
import SettingRow from '../components/SettingRow';
import SiemSettings from '../components/settings/SiemSettings';
import TaxiiSettings from '../components/settings/TaxiiSettings';

// ─── Settings model + store ────────────────────────────────────────────────

type ScanMode = 'fixture' | 'stdio' | 'http';
type WebhookFormat = 'generic' | 'slack' | 'teams';

interface Settings {
  capture: {
    defaultMode: ScanMode;
    httpPort: number;
  };
  alerts: {
    email: {
      enabled: boolean;
      host: string;
      port: number;
      from: string;
      to: string;
    };
    webhook: {
      enabled: boolean;
      url: string;
      format: WebhookFormat;
    };
  };
  retention: {
    contactsDays: 30 | 60 | 90;
    findingsDays: 90 | 180 | 365;
    alertsDays: 30 | 90 | 180;
  };
  privacy: {
    inFlightOnly: true; // locked
    outboundLookups: boolean;
  };
  enforcement: {
    enabled: boolean;
  };
}

const INITIAL: Settings = {
  capture: { defaultMode: 'fixture', httpPort: 8765 },
  alerts: {
    email: {
      enabled: false,
      host: 'smtp.example.com',
      port: 587,
      from: 'sentinel@example.com',
      to: 'security@example.com',
    },
    webhook: {
      enabled: false,
      url: '',
      format: 'generic',
    },
  },
  retention: {
    contactsDays: 60,
    findingsDays: 180,
    alertsDays: 90,
  },
  privacy: {
    inFlightOnly: true,
    outboundLookups: false,
  },
  // Enforcement is OPT-IN. Sentinel stays advisory until the operator
  // flips this toggle in Settings → Enforcement.
  enforcement: {
    enabled: false,
  },
};

interface SettingsStore {
  draft: Settings;
  saved: Settings;
  set: (mutator: (s: Settings) => void) => void;
  commit: () => void;
  reset: () => void;
  hydrate: (s: Settings) => void;
}

function clone(s: Settings): Settings {
  return JSON.parse(JSON.stringify(s)) as Settings;
}

// ─── DTO <-> UI mapping (backend uses snake_case TOML keys) ────────────────

function fromPersisted(p: PersistedSettings): Settings {
  return {
    capture: {
      defaultMode: p.capture.default_mode,
      httpPort: p.capture.http_port,
    },
    alerts: {
      email: {
        enabled: p.alerts.email.enabled,
        host: p.alerts.email.host,
        port: p.alerts.email.port,
        from: p.alerts.email.from,
        to: p.alerts.email.to,
      },
      webhook: {
        enabled: p.alerts.webhook.enabled,
        url: p.alerts.webhook.url,
        format: p.alerts.webhook.format,
      },
    },
    retention: {
      contactsDays: p.retention.contacts_days as 30 | 60 | 90,
      findingsDays: p.retention.findings_days as 90 | 180 | 365,
      alertsDays: p.retention.alerts_days as 30 | 90 | 180,
    },
    privacy: {
      inFlightOnly: true,
      outboundLookups: p.privacy.outbound_lookups,
    },
    enforcement: {
      // Default to OFF when older TOML files don't carry the block yet.
      enabled: p.enforcement?.enabled ?? false,
    },
  };
}

function toPersisted(s: Settings): PersistedSettings {
  return {
    capture: {
      default_mode: s.capture.defaultMode,
      http_port: s.capture.httpPort,
    },
    alerts: {
      email: { ...s.alerts.email },
      webhook: { ...s.alerts.webhook },
    },
    retention: {
      contacts_days: s.retention.contactsDays,
      findings_days: s.retention.findingsDays,
      alerts_days: s.retention.alertsDays,
    },
    privacy: {
      in_flight_only: true,
      outbound_lookups: s.privacy.outboundLookups,
    },
    enforcement: {
      enabled: s.enforcement.enabled,
    },
  };
}

const useSettings = create<SettingsStore>((setState) => ({
  draft: clone(INITIAL),
  saved: clone(INITIAL),
  set: (mutator) =>
    setState((state) => {
      const next = clone(state.draft);
      mutator(next);
      // Inspection-in-flight is non-negotiable.
      next.privacy.inFlightOnly = true;
      return { draft: next };
    }),
  commit: () =>
    setState((state) => ({ saved: clone(state.draft) })),
  reset: () =>
    setState((state) => ({ draft: clone(state.saved) })),
  hydrate: (loaded) =>
    setState(() => ({ draft: clone(loaded), saved: clone(loaded) })),
}));

// ─── Page ─────────────────────────────────────────────────────────────────

export default function SettingsPage() {
  const draft = useSettings((s) => s.draft);
  const saved = useSettings((s) => s.saved);
  const set = useSettings((s) => s.set);
  const commit = useSettings((s) => s.commit);
  const reset = useSettings((s) => s.reset);
  const hydrate = useSettings((s) => s.hydrate);

  const [savedAt, setSavedAt] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const savedTimer = useRef<number | null>(null);

  // ─── Webhook test state ─────────────────────────────────────────────────
  const [webhookTesting, setWebhookTesting] = useState(false);
  const [webhookResult, setWebhookResult] = useState<
    | { ok: true; status: number | null }
    | { ok: false; error: string }
    | null
  >(null);
  const webhookResultTimer = useRef<number | null>(null);

  const handleTestWebhook = async () => {
    if (!draft.alerts.webhook.url.trim() || webhookTesting) return;
    if (webhookResultTimer.current) window.clearTimeout(webhookResultTimer.current);
    setWebhookResult(null);
    setWebhookTesting(true);
    try {
      const res = await api.testWebhookChannel({
        url: draft.alerts.webhook.url,
        format: draft.alerts.webhook.format,
      });
      if (res.ok) {
        setWebhookResult({ ok: true, status: res.status });
      } else {
        setWebhookResult({
          ok: false,
          error: res.error ?? 'Unknown error',
        });
      }
    } catch (err) {
      setWebhookResult({
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setWebhookTesting(false);
      webhookResultTimer.current = window.setTimeout(
        () => setWebhookResult(null),
        6000,
      );
    }
  };

  useEffect(
    () => () => {
      if (webhookResultTimer.current)
        window.clearTimeout(webhookResultTimer.current);
    },
    [],
  );

  // Load persisted settings from the backend on mount.
  useEffect(() => {
    let cancelled = false;
    api
      .getSettings()
      .then((loaded) => {
        if (cancelled) return;
        hydrate(fromPersisted(loaded));
      })
      .catch(() => {
        // Defaults already in store; nothing to do.
      });
    return () => {
      cancelled = true;
    };
  }, [hydrate]);

  useEffect(
    () => () => {
      if (savedTimer.current) window.clearTimeout(savedTimer.current);
    },
    [],
  );

  const dirty = useMemo(
    () => JSON.stringify(draft) !== JSON.stringify(saved),
    [draft, saved],
  );

  const handleSave = async () => {
    setSaveError(null);
    try {
      await api.saveSettings(toPersisted(draft));
      commit();
      const ts = new Date();
      const hh = String(ts.getHours()).padStart(2, '0');
      const mm = String(ts.getMinutes()).padStart(2, '0');
      setSavedAt(`Settings saved · ${hh}:${mm}`);
      if (savedTimer.current) window.clearTimeout(savedTimer.current);
      savedTimer.current = window.setTimeout(() => setSavedAt(null), 3000);
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : String(err));
    }
  };

  const { data: appVersion } = useSWR<string>(
    'app_version',
    () => api.appVersion(),
  );
  const { data: compliance } = useSWR<ComplianceReference[]>(
    'compliance_references',
    () => api.complianceReferences(),
  );

  const frameworks = useMemo(() => {
    if (!compliance) return [] as string[];
    return Array.from(new Set(compliance.map((c) => c.framework)));
  }, [compliance]);

  return (
    <div className="animate-fade-up pb-28">
      <header className="mb-6">
        <h1 className="text-[28px] font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 text-[13px] text-sentinel-text-secondary">
          Configure capture, alert channels, retention windows and privacy
          posture.
        </p>
        <p className="mt-1 text-[11px] text-sentinel-text-tertiary">
          Persisted to <span className="font-mono">settings.toml</span> on save.
        </p>
      </header>

      <div className="grid grid-cols-1 min-[1100px]:grid-cols-2 gap-6">
        {/* ── Live monitoring ── */}
        <section
          className="card min-w-0 min-[1100px]:col-span-2"
          aria-labelledby="settings-live"
        >
          <SectionHeading id="settings-live" title="Live monitoring" />
          <LiveIntervalRow />
        </section>

        {/* ── Capture ── */}
        <section className="card min-w-0" aria-labelledby="settings-capture">
          <SectionHeading id="settings-capture" title="Capture" />
          <SettingRow
            label="Default scan mode"
            description="Used when starting a scan from the Live Scan tab without arguments."
          >
            <Segmented
              value={draft.capture.defaultMode}
              onChange={(v) =>
                set((s) => {
                  s.capture.defaultMode = v;
                })
              }
              options={[
                { value: 'fixture', label: 'Fixture' },
                { value: 'stdio', label: 'Stdio' },
                { value: 'http', label: 'HTTP' },
              ]}
            />
          </SettingRow>
          <SettingRow
            label="HTTP capture port"
            description="Local port the HTTP interceptor binds to."
            htmlForId="capture-http-port"
            last
          >
            <input
              id="capture-http-port"
              type="number"
              min={1024}
              max={65535}
              value={draft.capture.httpPort}
              onChange={(e) =>
                set((s) => {
                  s.capture.httpPort = Number(e.target.value) || 0;
                })
              }
              className="input w-28 text-right tabular-nums"
            />
          </SettingRow>
        </section>

        {/* ── Proxy capture (mode B) ── */}
        <section
          className="card min-w-0 min-[1100px]:col-span-2"
          aria-labelledby="settings-proxy"
        >
          <SectionHeading
            id="settings-proxy"
            title="Proxy capture (mode B) — experimental"
          />
          <ProxyCaptureRows />
        </section>

        {/* ── Alerts ── */}
        <section className="card min-w-0" aria-labelledby="settings-alerts">
          <SectionHeading id="settings-alerts" title="Alerts" />

          <SettingRow
            label="Email channel"
            description="Send critical findings to a mailbox over SMTP."
          >
            <div className="flex items-center gap-3">
              <TestEmailButton email={draft.alerts.email} />
              <Toggle
                checked={draft.alerts.email.enabled}
                onChange={(v) =>
                  set((s) => {
                    s.alerts.email.enabled = v;
                  })
                }
                ariaLabel="Enable email alerts"
              />
            </div>
          </SettingRow>
          <SettingRow
            label="SMTP host"
            htmlForId="alerts-smtp-host"
            align="top"
          >
            <input
              id="alerts-smtp-host"
              className="input w-64"
              value={draft.alerts.email.host}
              onChange={(e) =>
                set((s) => {
                  s.alerts.email.host = e.target.value;
                })
              }
              disabled={!draft.alerts.email.enabled}
            />
          </SettingRow>
          <SettingRow label="SMTP port" htmlForId="alerts-smtp-port">
            <input
              id="alerts-smtp-port"
              type="number"
              min={1}
              max={65535}
              className="input w-28 text-right tabular-nums"
              value={draft.alerts.email.port}
              onChange={(e) =>
                set((s) => {
                  s.alerts.email.port = Number(e.target.value) || 0;
                })
              }
              disabled={!draft.alerts.email.enabled}
            />
          </SettingRow>
          <SettingRow label="From" htmlForId="alerts-smtp-from">
            <input
              id="alerts-smtp-from"
              className="input w-64"
              value={draft.alerts.email.from}
              onChange={(e) =>
                set((s) => {
                  s.alerts.email.from = e.target.value;
                })
              }
              disabled={!draft.alerts.email.enabled}
            />
          </SettingRow>
          <SettingRow label="To" htmlForId="alerts-smtp-to">
            <input
              id="alerts-smtp-to"
              className="input w-64"
              value={draft.alerts.email.to}
              onChange={(e) =>
                set((s) => {
                  s.alerts.email.to = e.target.value;
                })
              }
              disabled={!draft.alerts.email.enabled}
            />
          </SettingRow>

          <SettingRow
            label="Webhook"
            description="POST every alert to a generic endpoint or chat connector."
          >
            <Toggle
              checked={draft.alerts.webhook.enabled}
              onChange={(v) =>
                set((s) => {
                  s.alerts.webhook.enabled = v;
                })
              }
              ariaLabel="Enable webhook alerts"
            />
          </SettingRow>
          <SettingRow label="Webhook URL" htmlForId="alerts-webhook-url" align="top">
            <div className="flex flex-col items-end gap-2">
              <div className="flex items-center gap-2">
                <input
                  id="alerts-webhook-url"
                  className="input w-64"
                  placeholder="https://hooks.example.com/T0000/B0000/…"
                  value={draft.alerts.webhook.url}
                  onChange={(e) =>
                    set((s) => {
                      s.alerts.webhook.url = e.target.value;
                    })
                  }
                  disabled={!draft.alerts.webhook.enabled}
                />
                <button
                  type="button"
                  className={clsx(
                    'btn',
                    webhookTesting &&
                      'animate-shimmer bg-[length:200%_100%] bg-gradient-to-r from-sentinel-blue/30 via-sentinel-purple/30 to-sentinel-blue/30',
                  )}
                  onClick={handleTestWebhook}
                  disabled={
                    !draft.alerts.webhook.url.trim() || webhookTesting
                  }
                  aria-label="Send test webhook"
                  title={
                    !draft.alerts.webhook.url.trim()
                      ? 'Enter a webhook URL first'
                      : 'POST a synthetic test alert to the configured URL'
                  }
                >
                  {webhookTesting ? 'Sending…' : 'Send test webhook'}
                </button>
              </div>
              {webhookResult && (
                <span
                  role="status"
                  aria-live="polite"
                  className={clsx(
                    'pill',
                    webhookResult.ok ? 'pill-green' : 'pill-red',
                  )}
                >
                  {webhookResult.ok
                    ? `✓ Webhook responded with HTTP ${webhookResult.status ?? 200}`
                    : `✗ Error: ${webhookResult.error}`}
                </span>
              )}
            </div>
          </SettingRow>
          <SettingRow label="Webhook format" last>
            <Segmented
              value={draft.alerts.webhook.format}
              onChange={(v) =>
                set((s) => {
                  s.alerts.webhook.format = v;
                })
              }
              disabled={!draft.alerts.webhook.enabled}
              options={[
                { value: 'generic', label: 'Generic' },
                { value: 'slack', label: 'Slack' },
                { value: 'teams', label: 'Teams' },
              ]}
            />
          </SettingRow>
        </section>

        {/* ── SIEM ── */}
        <section
          className="card min-w-0 min-[1100px]:col-span-2"
          aria-labelledby="settings-siem"
        >
          <SectionHeading id="settings-siem" title="SIEM" />
          <SiemSettings />
        </section>

        {/* ── STIX / TAXII ── */}
        <section
          className="card min-w-0 min-[1100px]:col-span-2"
          aria-labelledby="settings-taxii"
        >
          <SectionHeading id="settings-taxii" title="STIX / TAXII" />
          <p className="mb-2 text-[12px] text-sentinel-text-tertiary">
            Export findings as STIX 2.1 and push to a TAXII 2.1 collection
            (SOC/GRC integration).
          </p>
          <TaxiiSettings outboundEnabled={draft.privacy.outboundLookups} />
        </section>

        {/* ── Retention ── */}
        <section className="card min-w-0" aria-labelledby="settings-retention">
          <SectionHeading id="settings-retention" title="Retention" />
          <SettingRow
            label="Contacts history"
            description="How long captured client/server contacts are kept."
          >
            <DaysSlider
              value={draft.retention.contactsDays}
              options={[30, 60, 90]}
              onChange={(v) =>
                set((s) => {
                  s.retention.contactsDays = v as 30 | 60 | 90;
                })
              }
            />
          </SettingRow>
          <SettingRow
            label="Findings"
            description="Detection history retained for audits."
          >
            <DaysSlider
              value={draft.retention.findingsDays}
              options={[90, 180, 365]}
              onChange={(v) =>
                set((s) => {
                  s.retention.findingsDays = v as 90 | 180 | 365;
                })
              }
            />
          </SettingRow>
          <SettingRow
            label="Alerts"
            description="Retention of dispatched alert notifications."
            last
          >
            <DaysSlider
              value={draft.retention.alertsDays}
              options={[30, 90, 180]}
              onChange={(v) =>
                set((s) => {
                  s.retention.alertsDays = v as 30 | 90 | 180;
                })
              }
            />
          </SettingRow>
        </section>

        {/* ── Privacy ── */}
        <section className="card min-w-0" aria-labelledby="settings-privacy">
          <SectionHeading id="settings-privacy" title="Privacy" />
          <SettingRow
            label={
              <span className="inline-flex items-center gap-1.5">
                Inspection-in-flight only
                <Lock className="h-3 w-3 text-sentinel-text-tertiary" />
              </span>
            }
            description="Sentinel inspects MCP traffic in transit and never persists payload bodies."
          >
            <LockedTooltip text="Non-negotiable">
              <Toggle
                checked
                onChange={() => {}}
                disabled
                ariaLabel="Inspection-in-flight only (locked)"
              />
            </LockedTooltip>
          </SettingRow>
          <SettingRow
            label="Outbound calls (registries lookup)"
            description="Allow Sentinel to query public MCP registries to enrich fingerprints."
            last
          >
            <Toggle
              checked={draft.privacy.outboundLookups}
              onChange={(v) =>
                set((s) => {
                  s.privacy.outboundLookups = v;
                })
              }
              ariaLabel="Enable outbound registry lookups"
            />
          </SettingRow>
        </section>

        {/* ── Enforcement (experimental) ── */}
        <section
          className="card min-w-0 min-[1100px]:col-span-2"
          aria-labelledby="settings-enforcement"
        >
          <SectionHeading
            id="settings-enforcement"
            title="Enforcement (experimental)"
          />
          <SettingRow
            label={
              <span className="inline-flex items-center gap-1.5">
                Allow Sentinel to remove blocked servers from your AI client configs
                <AlertTriangle className="h-3 w-3 text-sentinel-orange" />
              </span>
            }
            description="When enabled, the Block action in the Approvals queue and the server detail drawer will rewrite the declaring config file on disk and write a timestamped backup next to it. Off by default — Sentinel stays advisory until you opt in."
            last
          >
            <Toggle
              checked={draft.enforcement.enabled}
              onChange={(v) =>
                set((s) => {
                  s.enforcement.enabled = v;
                })
              }
              ariaLabel="Enable enforcement mode"
            />
          </SettingRow>
        </section>

        {/* ── About ── */}
        <section
          className="card min-w-0 min-[1100px]:col-span-2"
          aria-labelledby="settings-about"
        >
          <SectionHeading id="settings-about" title="About" />
          <SettingRow label="App version" description="Sentinel MCP Desktop">
            <span className="font-mono text-[12px] text-sentinel-text-secondary">
              {appVersion ?? '…'}
            </span>
          </SettingRow>
          <SettingRow
            label="Compliance frameworks supported"
            description="Findings are mapped to identifiers from these frameworks."
          >
            <div className="flex flex-wrap gap-1.5 max-w-md justify-end">
              {frameworks.length === 0 ? (
                <span className="text-[12px] text-sentinel-text-tertiary">
                  Loading…
                </span>
              ) : (
                frameworks.map((f) => (
                  <span key={f} className="pill pill-blue">
                    {f}
                  </span>
                ))
              )}
            </div>
          </SettingRow>
          <SettingRow
            label={
              <span className="inline-flex items-center gap-1.5">
                <ShieldCheck className="h-3.5 w-3.5 text-sentinel-green" />
                Read-only by default
              </span>
            }
            description="Sentinel never blocks or rewrites MCP traffic. Approvals are advisory and require operator action."
            last
          >
            <span className="pill pill-green">Safe</span>
          </SettingRow>
        </section>
      </div>

      <FloatingActions visible={dirty} onCancel={reset} onSave={handleSave} />
      <SaveToast message={saveError ? `Save failed: ${saveError}` : savedAt} error={!!saveError} />
    </div>
  );
}

function SaveToast({
  message,
  error,
}: {
  message: string | null;
  error: boolean;
}) {
  return (
    <div
      className={clsx(
        'pointer-events-none fixed inset-x-0 bottom-24 z-30 flex justify-center px-6 transition-all duration-200',
        message ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-2',
      )}
      aria-live="polite"
      aria-hidden={!message}
    >
      <div
        className={clsx(
          'glass-soft rounded-pill px-3 py-1.5 text-[12px]',
          error ? 'text-sentinel-red' : 'text-sentinel-text-secondary',
        )}
      >
        {message ?? ''}
      </div>
    </div>
  );
}

// ─── Building blocks ──────────────────────────────────────────────────────

function SectionHeading({ id, title }: { id: string; title: string }) {
  return (
    <h2 id={id} className="section-heading mb-2">
      {title}
    </h2>
  );
}

interface SegmentedOption<T extends string> {
  value: T;
  label: string;
}

interface SegmentedProps<T extends string> {
  value: T;
  onChange: (v: T) => void;
  options: SegmentedOption<T>[];
  disabled?: boolean;
}

function Segmented<T extends string>({
  value,
  onChange,
  options,
  disabled,
}: SegmentedProps<T>) {
  return (
    <div
      role="radiogroup"
      className={clsx(
        'inline-flex items-center rounded-pill p-0.5 bg-white/5 border border-white/10',
        disabled && 'opacity-50',
      )}
    >
      {options.map((opt) => {
        const active = opt.value === value;
        return (
          <button
            key={opt.value}
            type="button"
            role="radio"
            aria-checked={active}
            disabled={disabled}
            onClick={() => onChange(opt.value)}
            className={clsx(
              'rounded-pill px-3 py-1 text-[12px] font-medium transition-all duration-150',
              active
                ? 'bg-white/15 text-white shadow-glass-soft'
                : 'text-sentinel-text-secondary hover:text-white',
            )}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

interface ToggleProps {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  ariaLabel?: string;
}

function Toggle({ checked, onChange, disabled, ariaLabel }: ToggleProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={ariaLabel}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={clsx(
        'relative inline-flex h-[26px] w-[44px] shrink-0 items-center rounded-pill transition-colors duration-200',
        checked
          ? 'bg-sentinel-blue shadow-glow-blue'
          : 'bg-white/10 border border-white/15',
        disabled && 'opacity-70 cursor-not-allowed',
      )}
    >
      <span
        className={clsx(
          'inline-block h-[20px] w-[20px] rounded-full bg-white shadow-md transition-transform duration-200',
          checked ? 'translate-x-[20px]' : 'translate-x-[3px]',
        )}
      />
    </button>
  );
}

interface DaysSliderProps {
  value: number;
  options: number[];
  onChange: (v: number) => void;
}

function DaysSlider({ value, options, onChange }: DaysSliderProps) {
  return (
    <div className="flex items-center gap-3">
      <div className="inline-flex rounded-pill p-0.5 bg-white/5 border border-white/10">
        {options.map((opt) => {
          const active = opt === value;
          return (
            <button
              key={opt}
              type="button"
              onClick={() => onChange(opt)}
              className={clsx(
                'rounded-pill px-3 py-1 text-[12px] font-medium tabular-nums transition-all duration-150',
                active
                  ? 'bg-white/15 text-white shadow-glass-soft'
                  : 'text-sentinel-text-secondary hover:text-white',
              )}
            >
              {opt}d
            </button>
          );
        })}
      </div>
    </div>
  );
}

interface LockedTooltipProps {
  text: string;
  children: React.ReactNode;
}

function LockedTooltip({ text, children }: LockedTooltipProps) {
  const [open, setOpen] = useState(false);
  const timer = useRef<number | null>(null);
  useEffect(() => () => {
    if (timer.current) window.clearTimeout(timer.current);
  }, []);
  const show = () => {
    if (timer.current) window.clearTimeout(timer.current);
    setOpen(true);
  };
  const hide = () => {
    timer.current = window.setTimeout(() => setOpen(false), 80);
  };
  return (
    <span
      className="relative inline-flex items-center"
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
    >
      {children}
      <span
        role="tooltip"
        className={clsx(
          'pointer-events-none absolute right-0 top-full mt-2 z-20 whitespace-nowrap',
          'glass-soft rounded-md px-2 py-1 text-[11px] text-sentinel-text-secondary',
          'inline-flex items-center gap-1 transition-opacity duration-150',
          open ? 'opacity-100' : 'opacity-0',
        )}
      >
        <Info className="h-3 w-3 text-sentinel-text-tertiary" />
        {text}
      </span>
    </span>
  );
}

// ─── Live monitoring interval row ─────────────────────────────────────────

const LIVE_INTERVAL_OPTIONS: { value: 10 | 30 | 60 | 300; label: string }[] = [
  { value: 10, label: '10 s' },
  { value: 30, label: '30 s' },
  { value: 60, label: '60 s' },
  { value: 300, label: '5 min' },
];

function LiveIntervalRow() {
  const { data, mutate } = useSWR<LiveStatus>(
    COMMANDS.getLiveStatus,
    () => api.getLiveStatus(),
    { refreshInterval: 5000, revalidateOnFocus: false },
  );

  const current = (data?.interval_secs ?? 30) as 10 | 30 | 60 | 300;
  const [pending, setPending] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleChange = async (v: 10 | 30 | 60 | 300) => {
    if (pending !== null || v === current) return;
    setPending(v);
    setError(null);
    try {
      await api.setLiveInterval(v);
      // Refresh both the local SWR cache and the global one used by the
      // sidebar badge in DashboardLayout.
      await mutate();
      await globalMutate(COMMANDS.getLiveStatus);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setPending(null);
    }
  };

  return (
    <SettingRow
      label="Background sweep interval"
      description="How often Sentinel re-scans the local MCP surface for new servers, findings and alerts. Updates the sidebar Live badge."
      last
    >
      <div className="flex flex-col items-end gap-1.5">
        <Segmented
          value={String(current) as '10' | '30' | '60' | '300'}
          onChange={(v) => handleChange(Number(v) as 10 | 30 | 60 | 300)}
          options={LIVE_INTERVAL_OPTIONS.map((opt) => ({
            value: String(opt.value) as '10' | '30' | '60' | '300',
            label: opt.label,
          }))}
          disabled={pending !== null}
        />
        {error ? (
          <span className="pill pill-red text-[11px]">Error: {error}</span>
        ) : pending !== null ? (
          <span className="text-[11px] text-sentinel-text-tertiary">
            Updating…
          </span>
        ) : null}
      </div>
    </SettingRow>
  );
}

// ─── Proxy capture (mode B) ──────────────────────────────────────────────
//
// Thin wrappers around the `proxy_start`, `proxy_stop` and `proxy_status`
// Tauri commands introduced in V11. We call `invoke` directly so this page
// doesn't need a corresponding entry on the shared `api` surface — keeps the
// change scoped to the UI layer.

interface ProxyStatus {
  running: boolean;
  port: number | null;
  upstream: string | null;
  events_seen: number;
}

async function proxyStart(port: number, upstream: string): Promise<void> {
  await invoke('proxy_start', { port, upstream });
}

async function proxyStop(): Promise<void> {
  await invoke('proxy_stop');
}

async function proxyStatus(): Promise<ProxyStatus> {
  try {
    return await invoke<ProxyStatus>('proxy_status');
  } catch {
    return { running: false, port: null, upstream: null, events_seen: 0 };
  }
}

function ProxyCaptureRows() {
  const { data, mutate } = useSWR<ProxyStatus>(
    'proxy_status',
    () => proxyStatus(),
    { refreshInterval: 3000, revalidateOnFocus: false },
  );

  const running = !!data?.running;
  const livePort = data?.port ?? null;
  const eventsSeen = data?.events_seen ?? 0;

  const [port, setPort] = useState<number>(8765);
  const [upstream, setUpstream] = useState<string>('');
  const [pending, setPending] = useState<'start' | 'stop' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const copiedTimer = useRef<number | null>(null);

  // Hydrate inputs from backend status (when running already on mount).
  useEffect(() => {
    if (data?.port && data.port !== port && !running) return;
    if (data?.port) setPort(data.port);
    if (data?.upstream && upstream === '') setUpstream(data.upstream);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data?.port, data?.upstream]);

  useEffect(
    () => () => {
      if (copiedTimer.current) window.clearTimeout(copiedTimer.current);
    },
    [],
  );

  const handleStart = async () => {
    if (pending) return;
    setError(null);
    if (!upstream.trim()) {
      setError('Upstream URL is required.');
      return;
    }
    if (!port || port < 1 || port > 65535) {
      setError('Port must be between 1 and 65535.');
      return;
    }
    setPending('start');
    try {
      await proxyStart(port, upstream.trim());
      await mutate();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setPending(null);
    }
  };

  const handleStop = async () => {
    if (pending) return;
    setError(null);
    setPending('stop');
    try {
      await proxyStop();
      await mutate();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setPending(null);
    }
  };

  const proxyUrl = `http://127.0.0.1:${running && livePort ? livePort : port}/mcp`;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(proxyUrl);
      setCopied(true);
      if (copiedTimer.current) window.clearTimeout(copiedTimer.current);
      copiedTimer.current = window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard may be unavailable; ignore silently.
    }
  };

  return (
    <>
      <SettingRow
        label="Enable proxy"
        description="Run an in-process HTTP proxy that forwards MCP traffic to an upstream server while emitting capture events."
      >
        <div className="flex items-center gap-3">
          <span
            className={clsx('pill', running ? 'pill-green' : 'pill-orange')}
            role="status"
            aria-live="polite"
          >
            <span
              className={clsx('dot', running ? 'dot-green' : 'dot-orange')}
            />
            {running
              ? `Running on :${livePort ?? port}`
              : 'Stopped'}
          </span>
          <Toggle
            checked={running}
            onChange={(v) => {
              if (v && !running) void handleStart();
              else if (!v && running) void handleStop();
            }}
            disabled={pending !== null || (!running && !upstream.trim())}
            ariaLabel="Enable proxy capture"
          />
        </div>
      </SettingRow>

      <SettingRow label="Port" htmlForId="proxy-port">
        <input
          id="proxy-port"
          type="number"
          min={1024}
          max={65535}
          value={port}
          onChange={(e) => setPort(Number(e.target.value) || 0)}
          disabled={running || pending !== null}
          className="input w-28 text-right tabular-nums"
        />
      </SettingRow>

      <SettingRow
        label="Upstream URL"
        description="Where the proxy forwards MCP requests. Required to start."
        htmlForId="proxy-upstream"
        align="top"
      >
        <input
          id="proxy-upstream"
          className="input w-72"
          placeholder="https://your-mcp-server.example.com/mcp"
          value={upstream}
          onChange={(e) => setUpstream(e.target.value)}
          disabled={running || pending !== null}
        />
      </SettingRow>

      <SettingRow label="Controls">
        <div className="flex items-center gap-2">
          <button
            type="button"
            className="btn"
            onClick={handleStart}
            disabled={
              running || pending !== null || !upstream.trim()
            }
            title={
              !upstream.trim()
                ? 'Set the upstream URL first'
                : 'Start the proxy listener'
            }
          >
            {pending === 'start' ? 'Starting…' : 'Start'}
          </button>
          <button
            type="button"
            className="btn"
            onClick={handleStop}
            disabled={!running || pending !== null}
          >
            {pending === 'stop' ? 'Stopping…' : 'Stop'}
          </button>
        </div>
      </SettingRow>

      <SettingRow
        label="Events captured"
        description="Total MCP requests/responses observed by the proxy since it started."
      >
        <span className="font-mono text-[12px] tabular-nums text-sentinel-text-secondary">
          {eventsSeen.toLocaleString()}
        </span>
      </SettingRow>

      <SettingRow
        label="Client redirect"
        description="Point your MCP client to this URL instead of the upstream directly."
        last
      >
        <div className="flex flex-col items-end gap-1.5">
          <div className="flex items-center gap-2">
            <code className="font-mono text-[12px] text-sentinel-text-secondary glass-soft rounded-md px-2 py-1">
              {proxyUrl}
            </code>
            <button
              type="button"
              className="btn"
              onClick={handleCopy}
              aria-label="Copy proxy URL"
            >
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          {error ? (
            <span className="pill pill-red text-[11px]">Error: {error}</span>
          ) : null}
        </div>
      </SettingRow>
    </>
  );
}

// ─── Test email button ────────────────────────────────────────────────────

interface EmailDraft {
  enabled: boolean;
  host: string;
  port: number;
  from: string;
  to: string;
}

interface TestEmailFeedback {
  ok: boolean;
  filePath: string | null;
  error: string | null;
}

function TestEmailButton({ email }: { email: EmailDraft }) {
  const [pending, setPending] = useState(false);
  const [feedback, setFeedback] = useState<TestEmailFeedback | null>(null);
  const timer = useRef<number | null>(null);

  useEffect(
    () => () => {
      if (timer.current) window.clearTimeout(timer.current);
    },
    [],
  );

  const configured =
    email.host.trim().length > 0 &&
    email.port > 0 &&
    email.from.trim().length > 0 &&
    email.to.trim().length > 0;

  const handleClick = async () => {
    if (pending) return;
    setPending(true);
    setFeedback(null);
    try {
      const result = await api.testEmailChannel({
        smtp_host: email.host,
        smtp_port: email.port,
        user: null,
        password: null,
        sender: email.from,
        recipient: email.to,
      });
      setFeedback({
        ok: result.ok,
        filePath: result.file_path,
        error: result.error,
      });
    } catch (err) {
      setFeedback({
        ok: false,
        filePath: null,
        error: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setPending(false);
      if (timer.current) window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setFeedback(null), 8000);
    }
  };

  const handleReveal = async () => {
    try {
      await api.openReportFile('/tmp/sentinel-emails/');
    } catch {
      // No-op; the dry-run write already succeeded.
    }
  };

  return (
    <div className="flex flex-col items-end gap-1.5">
      <button
        type="button"
        className="btn"
        onClick={handleClick}
        disabled={!configured || pending}
        title={
          configured
            ? 'Write a synthetic .eml to /tmp/sentinel-emails/ (dry-run)'
            : 'Configure SMTP host, port, sender and recipient first'
        }
      >
        {pending ? 'Sending…' : 'Send test email'}
      </button>
      {feedback && feedback.ok && feedback.filePath ? (
        <div className="flex items-center gap-2 text-[11px] text-sentinel-text-secondary">
          <span className="pill pill-green">
            Wrote {feedback.filePath}
          </span>
          <button
            type="button"
            className="text-sentinel-blue hover:underline"
            onClick={handleReveal}
          >
            Reveal in Finder
          </button>
        </div>
      ) : feedback && !feedback.ok ? (
        <span className="pill pill-red text-[11px]">
          Error: {feedback.error ?? 'unknown'}
        </span>
      ) : null}
    </div>
  );
}

interface FloatingActionsProps {
  visible: boolean;
  onCancel: () => void;
  onSave: () => void;
}

function FloatingActions({ visible, onCancel, onSave }: FloatingActionsProps) {
  return (
    <div
      className={clsx(
        'pointer-events-none fixed inset-x-0 bottom-0 sm:bottom-6 z-30 flex justify-stretch sm:justify-center px-0 sm:px-6 transition-all duration-200',
        visible
          ? 'opacity-100 translate-y-0'
          : 'opacity-0 translate-y-3 pointer-events-none',
      )}
      aria-hidden={!visible}
    >
      <div
        className={clsx(
          'glass-strong px-3 py-2 flex items-center gap-3 w-full sm:w-auto rounded-none sm:rounded-pill justify-between sm:justify-center',
          visible && 'pointer-events-auto',
        )}
      >
        <span className="text-[12px] text-sentinel-text-secondary pl-2">
          Unsaved changes
        </span>
        <div className="flex items-center gap-2">
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" onClick={onSave}>
            Save
          </button>
        </div>
      </div>
    </div>
  );
}
