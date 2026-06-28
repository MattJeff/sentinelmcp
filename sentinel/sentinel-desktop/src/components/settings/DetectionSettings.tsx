// DetectionSettings — Settings → Detection engines card (V0.6).
//
// Drives the hybrid-detection block (`settings.detection`) used by the live
// background scan, the active probe and the skills scan:
//   * YARA (local, offline) — ON by default. Pattern-matches tool
//     descriptions/schemas against the embedded signature set to catch
//     poisoning, hidden directives and exfiltration cues.
//   * Local LLM judge (Ollama) — OFF by default. When enabled, sends
//     suspicious tool surfaces to a model running on `llmUrl` for a second
//     opinion. The model runs on the operator's own machine, so the
//     zero-cloud guarantee holds: nothing ever leaves the host.
//
// Mirrors the ThreatFeed / SIEM / TAXII card pattern: the persisted prefs
// (yara / llm / llmUrl) live in the parent `SettingsPage` draft and are
// saved through `save_settings`; this component only renders the controls
// and the read-only list of embedded YARA rules (`list_yara_rules`).

import { useEffect, useState } from 'react';
import clsx from 'clsx';
import { ShieldCheck } from 'lucide-react';

import { api } from '../../api/tauri';
import type { YaraRules } from '../../api/contract';
import { useToast } from '../../hooks/useToast';
import SettingRow from '../SettingRow';

export interface DetectionSettingsProps {
  /** Mirror of `settings.detection.yara`. */
  yara: boolean;
  /** Mirror of `settings.detection.llm`. */
  llm: boolean;
  /** Mirror of `settings.detection.llmUrl`. */
  llmUrl: string;
  onYaraChange: (next: boolean) => void;
  onLlmChange: (next: boolean) => void;
  onLlmUrlChange: (next: string) => void;
}

/** Map a finding severity onto the matching badge class. */
function severityBadgeClass(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'badge-critical';
    case 'high':
      return 'badge-high';
    case 'medium':
      return 'badge-medium';
    default:
      return 'badge-info';
  }
}

export default function DetectionSettings({
  yara,
  llm,
  llmUrl,
  onYaraChange,
  onLlmChange,
  onLlmUrlChange,
}: DetectionSettingsProps) {
  const [rules, setRules] = useState<YaraRules | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const { toast } = useToast();

  // Hydrate the embedded YARA rule list once on mount. Read-only: the set is
  // compiled into the binary, the operator can only inspect it.
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .listYaraRules()
      .then((res) => {
        if (cancelled) return;
        setRules(res);
        setLoadError(null);
      })
      .catch((err) => {
        if (cancelled) return;
        const message = err instanceof Error ? err.message : String(err);
        setLoadError(message);
        toast({
          title: 'Could not load YARA rules',
          description: message,
          severity: 'high',
        });
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [toast]);

  return (
    <div>
      {/* Zero-cloud guarantee — surfaced up front so the privacy posture is
          unambiguous before the operator enables the optional LLM judge. */}
      <div className="mb-4 flex items-start gap-2 rounded-lg border border-sentinel-border-soft bg-sentinel-inset px-3 py-2">
        <ShieldCheck
          className="mt-0.5 h-4 w-4 shrink-0 text-sentinel-ok"
          aria-hidden="true"
        />
        <p className="max-w-prose text-caption text-sentinel-text-secondary">
          Both engines run entirely on this Mac — zero cloud. YARA matches
          locally compiled signatures, and the optional LLM judge talks only to
          a model you host yourself (Ollama). No tool surface or finding ever
          leaves your machine.
        </p>
      </div>

      <SettingRow
        label="YARA signatures"
        description="Local, offline pattern matching over every tool description and input schema. Flags hidden system directives, secrets references and network-exfiltration cues. Recommended on."
      >
        <Toggle
          checked={yara}
          onChange={onYaraChange}
          ariaLabel="Enable YARA detection engine"
        />
      </SettingRow>

      <SettingRow
        label="Local LLM judge (Ollama)"
        description="Optional second opinion: suspicious tool surfaces are sent to a large-language model running locally on your machine for a semantic review. Off by default; turning it on keeps the zero-cloud guarantee because the model is self-hosted."
      >
        <Toggle
          checked={llm}
          onChange={onLlmChange}
          ariaLabel="Enable local LLM judge"
        />
      </SettingRow>

      <SettingRow
        label="LLM endpoint"
        description="Base URL of your local Ollama server. Defaults to the standard localhost port."
        htmlForId="detection-llm-url"
        last
      >
        <input
          id="detection-llm-url"
          className="input w-72"
          placeholder="http://localhost:11434"
          value={llmUrl}
          onChange={(e) => onLlmUrlChange(e.target.value)}
          disabled={!llm}
          autoComplete="off"
          spellCheck={false}
        />
      </SettingRow>

      {/* ── Embedded YARA rules (read-only) ── */}
      <div className="border-t border-sentinel-border-soft pt-4">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-body font-medium text-sentinel-text-primary">
            Embedded YARA rules
          </h3>
          {rules ? (
            <span className="badge badge-neutral tabular-nums">
              {rules.rules.length} rule{rules.rules.length === 1 ? '' : 's'}
              {rules.sources_count > 0
                ? ` · ${rules.sources_count} source${rules.sources_count === 1 ? '' : 's'}`
                : ''}
            </span>
          ) : null}
        </div>
        <p className="mb-3 max-w-prose text-caption text-sentinel-text-tertiary">
          The signature set compiled into Sentinel. Read-only — these run
          whenever YARA is enabled above.
        </p>

        {loading ? (
          <p className="text-caption text-sentinel-text-tertiary">
            Loading rules…
          </p>
        ) : loadError ? (
          <span className="badge badge-critical">
            Error: {loadError}
          </span>
        ) : rules && rules.rules.length > 0 ? (
          <ul className="flex flex-col gap-2">
            {rules.rules.map((rule) => (
              <li
                key={rule.name}
                className="flex flex-col gap-1 rounded-lg border border-sentinel-border-soft bg-sentinel-inset px-3 py-2 sm:flex-row sm:items-center sm:justify-between sm:gap-4"
              >
                <div className="min-w-0">
                  <span className="block truncate font-mono text-caption text-sentinel-text-primary">
                    {rule.name}
                  </span>
                  {rule.description ? (
                    <span className="block max-w-prose text-caption text-sentinel-text-tertiary">
                      {rule.description}
                    </span>
                  ) : null}
                </div>
                <span
                  className={clsx(
                    'badge shrink-0 self-start sm:self-auto',
                    severityBadgeClass(rule.severity),
                  )}
                >
                  {rule.severity}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-caption text-sentinel-text-tertiary">
            No embedded rules found.
          </p>
        )}
      </div>
    </div>
  );
}

// ─── Local toggle ─────────────────────────────────────────────────────────
// Same shape as the inline toggle in SettingsPage / ThreatFeedSettings.

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
