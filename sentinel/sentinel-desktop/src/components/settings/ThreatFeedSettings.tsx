// ThreatFeedSettings — Settings → Threat Intel Feed tab.
//
// Mirrors the SIEM / TAXII card pattern:
//   * URL + auto-refresh toggle live in the parent `SettingsPage` draft
//     (persisted via `save_settings` alongside the rest of the prefs);
//   * a small read-only status row hydrates from `threat_feed_status`
//     on mount and after every successful refresh;
//   * a "Refresh now" button forces a remote fetch through
//     `threat_feed_refresh`. Gated by the global "Outbound calls"
//     toggle on the Rust side — when OFF, the button is disabled with
//     the canonical tooltip.
//
// The bundled YAML remains the source of truth of last resort: the
// cascade in `sentinel_discovery::threat_intel::refresh::charger_feed`
// transparently falls back to cache → bundled when the remote URL is
// unreachable, so this card never surfaces a "broken" state.

import { useEffect, useState } from 'react';
import clsx from 'clsx';

import { api, onThreatFeedRefreshed } from '../../api/tauri';
import type { ThreatFeedStatus } from '../../api/contract';
import { useToast } from '../../hooks/useToast';
import SettingRow from '../SettingRow';

export interface ThreatFeedSettingsProps {
  /** Mirror of `settings.threatFeed.url`. */
  url: string;
  /** Mirror of `settings.threatFeed.autoRefreshEnabled`. */
  autoRefreshEnabled: boolean;
  /**
   * Mirror of `settings.privacy.outboundLookups`. When `false`, the
   * "Refresh now" button is disabled with the canonical tooltip — the
   * operator has explicitly turned off outbound traffic so we refuse
   * to call the remote URL.
   */
  outboundEnabled: boolean;
  onUrlChange: (next: string) => void;
  onAutoRefreshChange: (next: boolean) => void;
}

function formatTimestamp(iso: string | null): string {
  if (!iso) return 'never';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function formatAge(seconds: number | null): string {
  if (seconds === null || seconds < 0) return '';
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86_400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86_400)}d ago`;
}

export default function ThreatFeedSettings({
  url,
  autoRefreshEnabled,
  outboundEnabled,
  onUrlChange,
  onAutoRefreshChange,
}: ThreatFeedSettingsProps) {
  const [status, setStatus] = useState<ThreatFeedStatus | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const { toast } = useToast();

  // Hydrate the status on mount + every time the background loop emits
  // `sentinel://threat-feed-refreshed`. This keeps the card live without
  // polling.
  useEffect(() => {
    let cancelled = false;
    api
      .threatFeedStatus()
      .then((s) => {
        if (!cancelled) setStatus(s);
      })
      .catch(() => {
        // Status is purely informational; failing silently is fine.
      });
    let unlisten: (() => void) | null = null;
    onThreatFeedRefreshed((s) => {
      if (!cancelled) setStatus(s);
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, []);

  const handleRefresh = async () => {
    if (refreshing || !outboundEnabled) return;
    setRefreshing(true);
    try {
      const fresh = await api.threatFeedRefresh();
      setStatus(fresh);
      toast({
        title: 'Threat feed refreshed',
        description: `Source: ${fresh.source} · ${fresh.entries_count} entries`,
        severity: 'info',
      });
    } catch (err) {
      toast({
        title: 'Could not refresh threat feed',
        description: err instanceof Error ? err.message : String(err),
        severity: 'high',
      });
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <div>
      <SettingRow
        label="Feed URL"
        description="Remote YAML endpoint the daily refresh pulls from. The bundled fallback remains the source of truth when this URL is unreachable."
        htmlForId="threat-feed-url"
      >
        <input
          id="threat-feed-url"
          className="input w-72"
          placeholder="https://example.com/threat_feed.yaml"
          value={url}
          onChange={(e) => onUrlChange(e.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
      </SettingRow>

      <SettingRow
        label="Auto-refresh daily"
        description="Refresh the cache from the remote URL every 24h, subject to the global Outbound calls toggle."
      >
        <Toggle
          checked={autoRefreshEnabled}
          onChange={onAutoRefreshChange}
          ariaLabel="Auto-refresh threat feed daily"
        />
      </SettingRow>

      <SettingRow
        label="Status"
        description="Where the active feed came from and how old it is. Updated whenever the cache is refreshed."
        last
      >
        <div className="flex flex-col gap-2 text-caption text-sentinel-text-secondary">
          <div className="flex items-center gap-2">
            <span className="text-sentinel-text-tertiary">Source:</span>
            <span
              className={clsx(
                'badge',
                status?.source === 'remote'
                  ? 'badge-ok'
                  : status?.source === 'cache'
                    ? 'badge-accent'
                    : 'badge-medium',
              )}
            >
              {status?.source ?? 'unknown'}
            </span>
          </div>
          <div className="tabular-nums">
            <span className="text-sentinel-text-tertiary">Last refresh:</span>{' '}
            {formatTimestamp(status?.last_refresh ?? null)}
            {status?.age_seconds !== null && status?.age_seconds !== undefined
              ? ` · ${formatAge(status.age_seconds)}`
              : ''}
          </div>
          <div className="tabular-nums">
            <span className="text-sentinel-text-tertiary">Entries:</span>{' '}
            {status?.entries_count ?? 0}
            {status?.version ? ` · v${status.version}` : ''}
          </div>
        </div>
      </SettingRow>

      <div className="flex items-center justify-end gap-2 border-t border-sentinel-border-soft pt-4">
        <button
          type="button"
          className="btn"
          onClick={handleRefresh}
          disabled={refreshing || !outboundEnabled}
          title={
            !outboundEnabled
              ? 'Disabled — Outbound calls are turned off.'
              : 'Fetch the latest threat feed from the remote URL'
          }
        >
          {refreshing ? 'Refreshing…' : 'Refresh now'}
        </button>
      </div>
    </div>
  );
}

// ─── Local toggle ─────────────────────────────────────────────────────────
// Same shape as the inline toggle in SettingsPage / TaxiiSettings.

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
