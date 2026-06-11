// TaxiiSettings — Settings → STIX / TAXII tab.
//
// Mirrors the SIEM card pattern: a small form that hydrates from disk on
// mount, persists via `taxii_save_config`, and can dispatch a synthetic
// STIX bundle through `taxii_test_send` to verify the round-trip against a
// TAXII 2.1 collection (Discovery → API root → collection → /objects).
//
// The "Send test" button is gated by the global "Outbound calls" toggle
// (`settings.privacy.outboundLookups`) — when the operator has disabled
// outbound traffic, the button is disabled with an explanatory tooltip and
// no network call is attempted.

import { useEffect, useState } from 'react';
import clsx from 'clsx';

import {
  taxii_get_config,
  taxii_save_config,
  taxii_test_send,
  type TaxiiAuth,
  type TaxiiConfig,
  type TaxiiTestResult,
} from '../../api/tauri';
import { useToast } from '../../hooks/useToast';
import SettingRow from '../SettingRow';

type AuthKind = TaxiiAuth['kind'];

interface TaxiiFormState {
  enabled: boolean;
  apiRootUrl: string;
  collectionId: string;
  authKind: AuthKind;
  basicUser: string;
  basicPass: string;
  bearerToken: string;
  verifyTls: boolean;
}

const EMPTY: TaxiiFormState = {
  enabled: false,
  apiRootUrl: '',
  collectionId: '',
  authKind: 'none',
  basicUser: '',
  basicPass: '',
  bearerToken: '',
  verifyTls: true,
};

function toConfig(state: TaxiiFormState): TaxiiConfig {
  let auth: TaxiiAuth;
  switch (state.authKind) {
    case 'basic':
      auth = { kind: 'basic', user: state.basicUser, pass: state.basicPass };
      break;
    case 'bearer':
      auth = { kind: 'bearer', token: state.bearerToken };
      break;
    default:
      auth = { kind: 'none' };
  }
  return {
    enabled: state.enabled,
    api_root_url: state.apiRootUrl,
    collection_id: state.collectionId,
    auth,
    verify_tls: state.verifyTls,
  };
}

function fromConfig(cfg: TaxiiConfig | null | undefined): TaxiiFormState {
  if (!cfg) return { ...EMPTY };
  const form: TaxiiFormState = {
    enabled: !!cfg.enabled,
    apiRootUrl: cfg.api_root_url ?? '',
    collectionId: cfg.collection_id ?? '',
    authKind: cfg.auth?.kind ?? 'none',
    basicUser: '',
    basicPass: '',
    bearerToken: '',
    verifyTls: cfg.verify_tls ?? true,
  };
  if (cfg.auth?.kind === 'basic') {
    form.basicUser = cfg.auth.user ?? '';
    form.basicPass = cfg.auth.pass ?? '';
  } else if (cfg.auth?.kind === 'bearer') {
    form.bearerToken = cfg.auth.token ?? '';
  }
  return form;
}

const AUTH_OPTIONS: { value: AuthKind; label: string }[] = [
  { value: 'none', label: 'None' },
  { value: 'basic', label: 'Basic' },
  { value: 'bearer', label: 'Bearer' },
];

export interface TaxiiSettingsProps {
  /**
   * Mirror of `settings.privacy.outboundLookups`. When `false`, the
   * "Send test" button is disabled — the operator has explicitly turned
   * off outbound traffic so we refuse to call the TAXII server.
   */
  outboundEnabled: boolean;
}

export default function TaxiiSettings({ outboundEnabled }: TaxiiSettingsProps) {
  const [form, setForm] = useState<TaxiiFormState>(EMPTY);
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [lastResult, setLastResult] = useState<
    | { ok: true; status: number | null; message: string }
    | { ok: false; status: number | null; message: string }
    | null
  >(null);
  const { toast } = useToast();

  // Hydrate from disk on mount.
  useEffect(() => {
    let cancelled = false;
    taxii_get_config()
      .then((loaded) => {
        if (cancelled) return;
        setForm(fromConfig(loaded));
      })
      .catch(() => {
        // Defaults already in state.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const update = <K extends keyof TaxiiFormState>(
    key: K,
    value: TaxiiFormState[K],
  ) => setForm((s) => ({ ...s, [key]: value }));

  const handleTest = async () => {
    if (testing || !outboundEnabled) return;
    setTesting(true);
    setLastResult(null);
    try {
      const res: TaxiiTestResult = await taxii_test_send();
      if (res.ok) {
        setLastResult({
          ok: true,
          status: res.status_code,
          message: res.message,
        });
        toast({
          title: 'TAXII test succeeded',
          description: res.message,
          severity: 'info',
        });
      } else {
        setLastResult({
          ok: false,
          status: res.status_code,
          message: res.message,
        });
        toast({
          title: 'TAXII test failed',
          description: res.message,
          severity: 'high',
        });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setLastResult({ ok: false, status: null, message });
      toast({
        title: 'TAXII test failed',
        description: message,
        severity: 'high',
      });
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    if (saving) return;
    setSaving(true);
    try {
      await taxii_save_config(toConfig(form));
      toast({
        title: 'TAXII config saved',
        severity: 'info',
      });
    } catch (err) {
      toast({
        title: 'Could not save TAXII config',
        description: err instanceof Error ? err.message : String(err),
        severity: 'high',
      });
    } finally {
      setSaving(false);
    }
  };

  const disabled = !form.enabled;

  return (
    <div>
      <SettingRow
        label="Enable"
        description="When on, Sentinel can push STIX 2.1 bundles to the TAXII collection configured below."
      >
        <Toggle
          checked={form.enabled}
          onChange={(v) => update('enabled', v)}
          ariaLabel="Enable STIX/TAXII export"
        />
      </SettingRow>

      <SettingRow
        label="API root URL"
        description="TAXII 2.1 API root (e.g. https://taxii.example.com/taxii2/)."
        htmlForId="taxii-api-root"
      >
        <input
          id="taxii-api-root"
          className="input w-72"
          placeholder="https://taxii.example.com/taxii2/"
          value={form.apiRootUrl}
          onChange={(e) => update('apiRootUrl', e.target.value)}
          disabled={disabled}
        />
      </SettingRow>

      <SettingRow
        label="Collection ID"
        description="UUID of the target TAXII collection."
        htmlForId="taxii-collection-id"
      >
        <input
          id="taxii-collection-id"
          className="input w-72"
          placeholder="00000000-0000-0000-0000-000000000000"
          value={form.collectionId}
          onChange={(e) => update('collectionId', e.target.value)}
          disabled={disabled}
        />
      </SettingRow>

      <SettingRow
        label="Authentication"
        description="How Sentinel authenticates to the TAXII server."
        htmlForId="taxii-auth-kind"
      >
        <select
          id="taxii-auth-kind"
          className="input w-40"
          value={form.authKind}
          onChange={(e) => update('authKind', e.target.value as AuthKind)}
          disabled={disabled}
        >
          {AUTH_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </SettingRow>

      {form.authKind === 'basic' ? (
        <>
          <SettingRow label="Username" htmlForId="taxii-basic-user">
            <input
              id="taxii-basic-user"
              className="input w-64"
              placeholder="taxii-user"
              value={form.basicUser}
              onChange={(e) => update('basicUser', e.target.value)}
              disabled={disabled}
              autoComplete="off"
            />
          </SettingRow>
          <SettingRow label="Password" htmlForId="taxii-basic-pass">
            <input
              id="taxii-basic-pass"
              type="password"
              className="input w-64"
              placeholder="••••••••"
              value={form.basicPass}
              onChange={(e) => update('basicPass', e.target.value)}
              disabled={disabled}
              autoComplete="off"
            />
          </SettingRow>
        </>
      ) : form.authKind === 'bearer' ? (
        <SettingRow
          label="Bearer token"
          description="Sent as 'Authorization: Bearer …'. Stored unencrypted in taxii.json."
          htmlForId="taxii-bearer-token"
        >
          <input
            id="taxii-bearer-token"
            type="password"
            className="input w-72"
            placeholder="eyJhbGciOi…"
            value={form.bearerToken}
            onChange={(e) => update('bearerToken', e.target.value)}
            disabled={disabled}
            autoComplete="off"
          />
        </SettingRow>
      ) : null}

      <SettingRow
        label="Verify TLS"
        description="Validate the TAXII server certificate. Keep on outside isolated test labs."
        last
      >
        <Toggle
          checked={form.verifyTls}
          onChange={(v) => update('verifyTls', v)}
          disabled={disabled}
          ariaLabel="Verify TLS certificates"
        />
      </SettingRow>

      <div className="flex items-center justify-between gap-4 border-t border-sentinel-border-soft pt-4">
        <div className="min-h-[20px] min-w-0 flex-1">
          {lastResult ? (
            <span
              role="status"
              aria-live="polite"
              className={clsx(
                'inline-flex items-center gap-2 text-caption',
                lastResult.ok
                  ? 'text-sentinel-ok'
                  : 'text-sentinel-critical',
              )}
            >
              <span
                aria-hidden="true"
                className={clsx(
                  'dot shrink-0',
                  lastResult.ok ? 'dot-ok' : 'dot-critical',
                )}
              />
              {lastResult.ok
                ? `Test OK${lastResult.status !== null ? ` · HTTP ${lastResult.status}` : ''} — ${lastResult.message}`
                : `Test failed${lastResult.status !== null ? ` · HTTP ${lastResult.status}` : ''} — ${lastResult.message}`}
            </span>
          ) : null}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <button
            type="button"
            className="btn"
            onClick={handleTest}
            disabled={testing || saving || !outboundEnabled || disabled}
            title={
              !outboundEnabled
                ? 'Disabled — Outbound calls are turned off.'
                : disabled
                  ? 'Enable STIX/TAXII first'
                  : 'POST a synthetic STIX bundle to the configured collection'
            }
          >
            {testing ? 'Sending…' : 'Send test'}
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={handleSave}
            disabled={testing || saving}
          >
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Local toggle ─────────────────────────────────────────────────────────
// Mirrors the inline `Toggle` used in `SettingsPage.tsx` so this card keeps
// the same affordance without reaching across files for a shared primitive.

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
        'focus-visible:outline-none focus-visible:shadow-focus',
        checked
          ? 'bg-sentinel-accent'
          : 'bg-white/10 border border-sentinel-border-strong',
        disabled && 'opacity-40 cursor-not-allowed',
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
