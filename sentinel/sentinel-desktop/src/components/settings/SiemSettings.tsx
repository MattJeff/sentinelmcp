// SiemSettings — Settings → SIEM tab.
//
// Renders a single card containing three sub-tabs (Splunk HEC, Elastic, Syslog)
// each exposing the fields required to dispatch an alert through the matching
// `sentinel_alerts::sinks::*` Rust client. Two buttons per tab:
//
//   * "Send test alert" — calls `siem_test_send` with the live form values.
//     Surfaces a toast on success/failure (does **not** persist anything).
//   * "Save"            — calls `siem_save_config` to persist the current
//     sub-tab's config to `siem.json` on disk.
//
// Hydrates the form from `siem_get_config` on mount so previously-saved
// settings come back across launches.

import { useEffect, useState } from 'react';
import clsx from 'clsx';

import { api } from '../../api/tauri';
import type { SiemConfig, SiemKind, SyslogTransport } from '../../api/contract';
import { useToast } from '../../hooks/useToast';
import SettingRow from '../SettingRow';

interface SplunkForm {
  url: string;
  token: string;
}

interface ElasticForm {
  url: string;
  index: string;
  user: string;
  pass: string;
}

interface SyslogForm {
  addr: string;
  transport: SyslogTransport;
  tlsCaPemPath: string;
}

interface SiemFormState {
  splunk: SplunkForm;
  elastic: ElasticForm;
  syslog: SyslogForm;
}

const EMPTY: SiemFormState = {
  splunk: { url: '', token: '' },
  elastic: { url: '', index: '', user: '', pass: '' },
  syslog: { addr: '', transport: 'udp', tlsCaPemPath: '' },
};

const SYSLOG_TRANSPORT_OPTIONS: { value: SyslogTransport; label: string }[] = [
  { value: 'udp', label: 'UDP (default)' },
  { value: 'tcp', label: 'TCP' },
  { value: 'tls', label: 'TLS' },
];

/** Map the wire-level `transport` string to the strict `SyslogTransport` union. */
function normalizeTransport(raw: string | null | undefined): SyslogTransport {
  const v = (raw ?? '').trim().toLowerCase();
  if (v === 'tcp') return 'tcp';
  if (v === 'tls') return 'tls';
  return 'udp';
}

function toConfig(kind: SiemKind, state: SiemFormState): SiemConfig {
  switch (kind) {
    case 'splunk':
      return {
        kind: 'splunk',
        url: state.splunk.url || null,
        token: state.splunk.token || null,
        index: null,
        user: null,
        pass: null,
        addr: null,
      };
    case 'elastic':
      return {
        kind: 'elastic',
        url: state.elastic.url || null,
        token: null,
        index: state.elastic.index || null,
        user: state.elastic.user || null,
        pass: state.elastic.pass || null,
        addr: null,
      };
    case 'syslog': {
      const transport = state.syslog.transport;
      return {
        kind: 'syslog',
        url: null,
        token: null,
        index: null,
        user: null,
        pass: null,
        addr: state.syslog.addr || null,
        transport,
        // Only forward the CA PEM path on the TLS branch — keeping it
        // attached when the operator flips back to UDP/TCP would be
        // confusing on next load.
        tls_ca_pem_path:
          transport === 'tls' && state.syslog.tlsCaPemPath
            ? state.syslog.tlsCaPemPath
            : null,
      };
    }
  }
}

function fromConfig(cfg: SiemConfig | null | undefined): {
  active: SiemKind;
  form: SiemFormState;
} {
  const form: SiemFormState = {
    splunk: { ...EMPTY.splunk },
    elastic: { ...EMPTY.elastic },
    syslog: { ...EMPTY.syslog },
  };
  let active: SiemKind = 'splunk';
  if (cfg && cfg.kind) {
    if (cfg.kind === 'elastic') {
      active = 'elastic';
      form.elastic = {
        url: cfg.url ?? '',
        index: cfg.index ?? '',
        user: cfg.user ?? '',
        pass: cfg.pass ?? '',
      };
    } else if (cfg.kind === 'syslog') {
      active = 'syslog';
      form.syslog = {
        addr: cfg.addr ?? '',
        transport: normalizeTransport(
          typeof cfg.transport === 'string' ? cfg.transport : null,
        ),
        tlsCaPemPath: cfg.tls_ca_pem_path ?? '',
      };
    } else {
      active = 'splunk';
      form.splunk = { url: cfg.url ?? '', token: cfg.token ?? '' };
    }
  }
  return { active, form };
}

const TABS: { value: SiemKind; label: string }[] = [
  { value: 'splunk', label: 'Splunk HEC' },
  { value: 'elastic', label: 'Elastic' },
  { value: 'syslog', label: 'Syslog' },
];

export interface SiemSettingsProps {
  /**
   * Mirror of `settings.privacy.outboundLookups`. When `false`, the
   * "Send test alert" button is disabled — the operator has explicitly
   * turned off outbound traffic so we refuse to dispatch to a SIEM sink.
   */
  outboundEnabled: boolean;
}

export default function SiemSettings({ outboundEnabled }: SiemSettingsProps) {
  const [active, setActive] = useState<SiemKind>('splunk');
  const [form, setForm] = useState<SiemFormState>(EMPTY);
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const { toast } = useToast();

  // Hydrate from disk on mount.
  useEffect(() => {
    let cancelled = false;
    api
      .siemGetConfig()
      .then((loaded) => {
        if (cancelled) return;
        const { active: a, form: f } = fromConfig(loaded);
        setActive(a);
        setForm(f);
      })
      .catch(() => {
        // Defaults already in state.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleTest = async () => {
    if (testing || !outboundEnabled) return;
    setTesting(true);
    try {
      await api.siemTestSend(toConfig(active, form));
      toast({
        title: `Test alert sent via ${tabLabel(active)}`,
        description: 'The sink accepted the synthetic alert.',
        severity: 'info',
      });
    } catch (err) {
      toast({
        title: `Test alert failed (${tabLabel(active)})`,
        description: err instanceof Error ? err.message : String(err),
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
      await api.siemSaveConfig(toConfig(active, form));
      toast({
        title: `SIEM config saved (${tabLabel(active)})`,
        severity: 'info',
      });
    } catch (err) {
      toast({
        title: 'Could not save SIEM config',
        description: err instanceof Error ? err.message : String(err),
        severity: 'high',
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <div
        role="tablist"
        aria-label="SIEM sink"
        className="mb-4 inline-flex items-center rounded-pill p-0.5 bg-white/5 border border-white/10"
      >
        {TABS.map((t) => {
          const isActive = t.value === active;
          return (
            <button
              key={t.value}
              type="button"
              role="tab"
              aria-selected={isActive}
              onClick={() => setActive(t.value)}
              className={clsx(
                'rounded-pill px-3 py-1 text-[12px] font-medium transition-all duration-150',
                isActive
                  ? 'bg-white/15 text-white shadow-glass-soft'
                  : 'text-sentinel-text-secondary hover:text-white',
              )}
            >
              {t.label}
            </button>
          );
        })}
      </div>

      {active === 'splunk' ? (
        <SplunkTab
          value={form.splunk}
          onChange={(next) => setForm((s) => ({ ...s, splunk: next }))}
        />
      ) : active === 'elastic' ? (
        <ElasticTab
          value={form.elastic}
          onChange={(next) => setForm((s) => ({ ...s, elastic: next }))}
        />
      ) : (
        <SyslogTab
          value={form.syslog}
          onChange={(next) => setForm((s) => ({ ...s, syslog: next }))}
        />
      )}

      <div className="flex items-center justify-end gap-2 pt-4">
        <button
          type="button"
          className={clsx(
            'btn',
            testing &&
              'animate-shimmer bg-[length:200%_100%] bg-gradient-to-r from-sentinel-blue/30 via-sentinel-purple/30 to-sentinel-blue/30',
          )}
          onClick={handleTest}
          disabled={testing || saving || !outboundEnabled}
          title={
            !outboundEnabled
              ? 'Disabled — Outbound calls are turned off.'
              : 'Dispatch a synthetic alert through the selected SIEM sink'
          }
        >
          {testing ? 'Sending…' : 'Send test alert'}
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
  );
}

function tabLabel(kind: SiemKind): string {
  return TABS.find((t) => t.value === kind)?.label ?? kind;
}

// ─── Sub-tab forms ────────────────────────────────────────────────────────

interface SplunkTabProps {
  value: SplunkForm;
  onChange: (next: SplunkForm) => void;
}

function SplunkTab({ value, onChange }: SplunkTabProps) {
  return (
    <>
      <SettingRow
        label="HEC URL"
        description="Splunk HTTP Event Collector base URL (e.g. https://splunk.example.com:8088)."
        htmlForId="siem-splunk-url"
      >
        <input
          id="siem-splunk-url"
          className="input w-72"
          placeholder="https://splunk.example.com:8088"
          value={value.url}
          onChange={(e) => onChange({ ...value, url: e.target.value })}
        />
      </SettingRow>
      <SettingRow
        label="HEC token"
        description="Authorization token. Stored unencrypted in siem.json."
        htmlForId="siem-splunk-token"
        last
      >
        <input
          id="siem-splunk-token"
          type="password"
          className="input w-72"
          placeholder="00000000-0000-0000-0000-000000000000"
          value={value.token}
          onChange={(e) => onChange({ ...value, token: e.target.value })}
          autoComplete="off"
        />
      </SettingRow>
    </>
  );
}

interface ElasticTabProps {
  value: ElasticForm;
  onChange: (next: ElasticForm) => void;
}

function ElasticTab({ value, onChange }: ElasticTabProps) {
  return (
    <>
      <SettingRow
        label="Cluster base URL"
        description="Elasticsearch cluster URL (e.g. https://es.example.com:9200)."
        htmlForId="siem-elastic-url"
      >
        <input
          id="siem-elastic-url"
          className="input w-72"
          placeholder="https://es.example.com:9200"
          value={value.url}
          onChange={(e) => onChange({ ...value, url: e.target.value })}
        />
      </SettingRow>
      <SettingRow
        label="Index"
        description="Destination index for the alerts."
        htmlForId="siem-elastic-index"
      >
        <input
          id="siem-elastic-index"
          className="input w-64"
          placeholder="sentinel-alerts"
          value={value.index}
          onChange={(e) => onChange({ ...value, index: e.target.value })}
        />
      </SettingRow>
      <SettingRow
        label="Username"
        description="HTTP Basic auth (optional)."
        htmlForId="siem-elastic-user"
      >
        <input
          id="siem-elastic-user"
          className="input w-64"
          placeholder="elastic"
          value={value.user}
          onChange={(e) => onChange({ ...value, user: e.target.value })}
          autoComplete="off"
        />
      </SettingRow>
      <SettingRow
        label="Password"
        htmlForId="siem-elastic-pass"
        last
      >
        <input
          id="siem-elastic-pass"
          type="password"
          className="input w-64"
          placeholder="••••••••"
          value={value.pass}
          onChange={(e) => onChange({ ...value, pass: e.target.value })}
          autoComplete="off"
        />
      </SettingRow>
    </>
  );
}

interface SyslogTabProps {
  value: SyslogForm;
  onChange: (next: SyslogForm) => void;
}

function SyslogTab({ value, onChange }: SyslogTabProps) {
  // Standard collector ports: 514/udp for legacy syslog, 6514/tcp+tls for
  // RFC 5425 (TLS) / RFC 6587 (TCP framing). We mirror that convention in
  // the placeholder so the operator gets a sane hint per transport.
  const addrPlaceholder =
    value.transport === 'udp' ? '127.0.0.1:514' : '127.0.0.1:6514';

  const handlePickCaPem = async () => {
    try {
      const picked = await api.siemPickCaPem();
      if (picked) {
        onChange({ ...value, tlsCaPemPath: picked });
      }
    } catch {
      // Picker errors are non-fatal — leave the current value in place.
    }
  };

  const isTls = value.transport === 'tls';

  return (
    <>
      <SettingRow
        label="Destination"
        description={
          value.transport === 'udp'
            ? 'Syslog collector host:port over UDP (RFC 5424).'
            : value.transport === 'tcp'
              ? 'Syslog collector host:port over TCP (RFC 6587 octet-counting).'
              : 'Syslog collector host:port over TLS (RFC 5425).'
        }
        htmlForId="siem-syslog-addr"
      >
        <input
          id="siem-syslog-addr"
          className="input w-64"
          placeholder={addrPlaceholder}
          value={value.addr}
          onChange={(e) => onChange({ ...value, addr: e.target.value })}
        />
      </SettingRow>
      <SettingRow
        label="Transport"
        description="Wire transport used to reach the syslog collector."
        htmlForId="siem-syslog-transport"
        last={!isTls}
      >
        <select
          id="siem-syslog-transport"
          className="input w-40"
          value={value.transport}
          onChange={(e) =>
            onChange({
              ...value,
              transport: e.target.value as SyslogTransport,
            })
          }
        >
          {SYSLOG_TRANSPORT_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </SettingRow>
      {isTls && (
        <SettingRow
          label="Custom CA (PEM)"
          description="Optional. If empty, system trust store is used."
          htmlForId="siem-syslog-ca-pem"
          last
        >
          <input
            id="siem-syslog-ca-pem"
            className="input w-64"
            placeholder="/etc/sentinel/ca.pem"
            value={value.tlsCaPemPath}
            onChange={(e) =>
              onChange({ ...value, tlsCaPemPath: e.target.value })
            }
          />
          <button
            type="button"
            className="btn"
            onClick={handlePickCaPem}
            title="Browse for a custom CA bundle (PEM / CRT / CER)"
          >
            Browse…
          </button>
        </SettingRow>
      )}
    </>
  );
}
