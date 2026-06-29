// SkillsPanel — surface the Claude/agent skills installed on this Mac and
// flag the ones whose content trips the hybrid-detection pipeline.
//
// Skills are not MCP servers — they are local instruction artefacts
// (SKILL.md / agent .md) that the agent silently follows. A poisoned skill
// can smuggle hidden directives, exfiltrate secrets, or line-jump ahead of
// the operator's own prompt. `scan_skills` runs each artefact's content
// through the same detectors used for tool descriptions and returns the
// findings here (they are deliberately NOT persisted to the server store).
//
// Layout: skills grouped per declaring client. Risky skills (with at least
// one finding) float to the top of their group, get a red accent, and carry
// a plain-English explanation of *why* they were flagged.

import { useMemo } from 'react';
import useSWR from 'swr';
import clsx from 'clsx';
import {
  AlertTriangle,
  Bot,
  Loader2,
  ScrollText,
  ShieldCheck,
  Wand2,
} from 'lucide-react';

import { api } from '@/api/tauri';
import {
  COMMANDS,
  type Severity,
  type SkillFinding,
  type SkillScan,
} from '@/api/contract';
import { useToast } from '@/hooks/useToast';

/** Human-readable client name for the kebab-case `client` identifier. */
const CLIENT_LABELS: Record<string, string> = {
  'claude-desktop': 'Claude Desktop',
  'claude-code-cli': 'Claude Code CLI',
  cursor: 'Cursor',
  windsurf: 'Windsurf',
  zed: 'Zed',
  vscode: 'VS Code',
  continue: 'Continue',
  aider: 'Aider',
  goose: 'Goose',
  codex: 'Codex',
  antigravity: 'Antigravity',
  'lm-studio': 'LM Studio',
};

function clientLabel(kind: string): string {
  if (CLIENT_LABELS[kind]) return CLIENT_LABELS[kind];
  return kind
    .split(/[-_]/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

function severityBadgeClass(s: Severity): string {
  switch (s) {
    case 'critical':
      return 'badge badge-critical';
    case 'high':
      return 'badge badge-high';
    case 'medium':
      return 'badge badge-medium';
    default:
      return 'badge badge-neutral';
  }
}

/** Rank a skill's worst finding so risky artefacts sort to the top. */
function severityRank(s: Severity): number {
  switch (s) {
    case 'critical':
      return 3;
    case 'high':
      return 2;
    case 'medium':
      return 1;
    default:
      return 0;
  }
}

function worstSeverity(findings: SkillFinding[]): Severity {
  let worst: Severity = 'info';
  for (const f of findings) {
    if (severityRank(f.severity) > severityRank(worst)) worst = f.severity;
  }
  return worst;
}

/**
 * Translate a snake_case `finding_type` into a plain-English sentence the
 * operator can act on, e.g. « This skill's instructions try to read ~/.ssh ».
 * The backend `detail` carries the literal evidence; this lead frames *what
 * kind* of abuse the pattern represents.
 */
function pedagogicalLead(findingType: string): string {
  const t = findingType.toLowerCase();
  if (t.includes('poison')) {
    return "This skill's instructions try to steer the agent off its task (tool poisoning).";
  }
  if (t.includes('smuggl')) {
    return 'This skill smuggles in hidden behaviour the operator never sees in plain text.';
  }
  if (t.includes('line') && (t.includes('jump') || t.includes('jmp'))) {
    return "This skill injects instructions ahead of the operator's own prompt (line-jumping).";
  }
  if (t.includes('linejump')) {
    return "This skill injects instructions ahead of the operator's own prompt (line-jumping).";
  }
  if (t.includes('secret') || t.includes('exfil') || t.includes('credential')) {
    return "This skill's instructions reach for secrets or push data off your Mac.";
  }
  if (t.includes('command') || t.includes('exec') || t.includes('shell')) {
    return 'This skill tries to run shell commands hidden inside its instructions.';
  }
  if (t.includes('memory') || t.includes('persist')) {
    return 'This skill tries to plant persistent instructions in the agent memory.';
  }
  if (t.includes('injection') || t.includes('prompt')) {
    return "This skill contains a prompt-injection payload aimed at the agent.";
  }
  return "This skill's instructions contain a suspicious pattern that was flagged.";
}

interface ClientGroup {
  client: string;
  label: string;
  skills: SkillScan[];
  flaggedCount: number;
}

function SkillCard({ skill }: { skill: SkillScan }) {
  const flagged = skill.findings.length > 0;
  const ArtefactIcon = skill.artifact_type === 'agent' ? Bot : Wand2;
  const worst = flagged ? worstSeverity(skill.findings) : 'info';

  return (
    <div
      className={clsx(
        'glass-soft flex flex-col gap-3 rounded-lg p-3 border-l-2 transition-colors duration-150',
        flagged
          ? 'border-sentinel-critical bg-sentinel-critical-bg'
          : 'border-transparent hover:bg-sentinel-raised hover:border-sentinel-border-strong',
      )}
    >
      {/* Top row — identity */}
      <div className="flex items-start gap-3">
        <div
          className={clsx(
            'h-8 w-8 shrink-0 rounded-lg border flex items-center justify-center',
            flagged
              ? 'border-sentinel-critical-border bg-sentinel-critical-bg'
              : 'border-sentinel-border bg-white/4',
          )}
        >
          <ArtefactIcon
            className={clsx(
              'h-4 w-4',
              flagged ? 'text-sentinel-critical' : 'text-sentinel-text-secondary',
            )}
            aria-hidden
          />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-body font-medium text-sentinel-text-primary truncate">
              {skill.name}
            </span>
            <span className="badge badge-neutral capitalize">
              {skill.artifact_type}
            </span>
            <span className="badge badge-neutral capitalize">{skill.scope}</span>
            {flagged ? (
              <span className={clsx(severityBadgeClass(worst), 'tabular-nums')}>
                <AlertTriangle className="h-3 w-3" aria-hidden />
                {skill.findings.length} finding
                {skill.findings.length === 1 ? '' : 's'}
              </span>
            ) : (
              <span className="badge badge-ok">
                <ShieldCheck className="h-3 w-3" aria-hidden />
                Clean
              </span>
            )}
          </div>
          {skill.description && (
            <div className="mt-1 text-caption text-sentinel-text-secondary line-clamp-2">
              {skill.description}
            </div>
          )}
          <div
            className="mt-1 font-mono text-[10px] text-sentinel-text-tertiary truncate"
            title={skill.path}
          >
            {skill.path}
          </div>
        </div>
      </div>

      {/* Findings — pedagogical explanation per hit */}
      {flagged && (
        <ul className="flex flex-col gap-2">
          {skill.findings.map((f, i) => (
            <li
              key={`${f.finding_type}-${i}`}
              className="rounded-md border border-sentinel-critical-border bg-sentinel-inset px-3 py-2"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className={severityBadgeClass(f.severity)}>
                  {f.severity}
                </span>
                <span className="text-caption font-medium text-sentinel-text-primary">
                  {f.title}
                </span>
              </div>
              <p className="mt-1 text-caption text-sentinel-text-secondary">
                {pedagogicalLead(f.finding_type)}
              </p>
              {f.detail && (
                <p
                  className="mt-1 text-[11px] text-sentinel-text-tertiary"
                  title={f.detail}
                >
                  {f.detail}
                </p>
              )}
              {f.compliance_refs.length > 0 && (
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {f.compliance_refs.map((r) => (
                    <span
                      key={r}
                      className="badge badge-neutral !px-1.5 !py-0 !text-[10px] !tracking-normal normal-case"
                    >
                      {r}
                    </span>
                  ))}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function SkillsPanel() {
  const { toast } = useToast();

  const { data, isValidating, error } = useSWR<SkillScan[]>(
    COMMANDS.scanSkills,
    api.scanSkills,
    {
      revalidateOnFocus: false,
      revalidateOnReconnect: false,
      onError: (err) => {
        toast({
          title: 'Skills scan failed',
          description: err instanceof Error ? err.message : String(err),
          severity: 'high',
        });
      },
    },
  );

  const skills = data ?? [];
  const flaggedTotal = skills.reduce(
    (acc, s) => acc + (s.findings.length > 0 ? 1 : 0),
    0,
  );

  // Group by declaring client; risky skills float to the top of each group.
  const groups = useMemo<ClientGroup[]>(() => {
    const byClient = new Map<string, SkillScan[]>();
    for (const s of skills) {
      const list = byClient.get(s.client) ?? [];
      list.push(s);
      byClient.set(s.client, list);
    }
    const out: ClientGroup[] = [];
    for (const [client, list] of byClient) {
      const sorted = [...list].sort((a, b) => {
        const aw = a.findings.length > 0 ? severityRank(worstSeverity(a.findings)) : -1;
        const bw = b.findings.length > 0 ? severityRank(worstSeverity(b.findings)) : -1;
        if (aw !== bw) return bw - aw;
        return a.name.localeCompare(b.name);
      });
      out.push({
        client,
        label: clientLabel(client),
        skills: sorted,
        flaggedCount: sorted.filter((s) => s.findings.length > 0).length,
      });
    }
    // Clients with risky skills first, then alphabetically.
    out.sort((a, b) => {
      if ((b.flaggedCount > 0 ? 1 : 0) !== (a.flaggedCount > 0 ? 1 : 0)) {
        return (b.flaggedCount > 0 ? 1 : 0) - (a.flaggedCount > 0 ? 1 : 0);
      }
      return a.label.localeCompare(b.label);
    });
    return out;
  }, [skills]);

  return (
    <section className="card flex flex-col gap-6">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="flex items-start gap-3">
          <div className="h-9 w-9 shrink-0 rounded-lg bg-sentinel-inset border border-sentinel-border flex items-center justify-center">
            <ScrollText
              className="h-4.5 w-4.5 text-sentinel-text-secondary"
              aria-hidden
            />
          </div>
          <div className="flex flex-col gap-1">
            <h3 className="text-title text-sentinel-text-primary">
              Skill &amp; agent security
              {skills.length > 0 && (
                <span className="text-sentinel-text-tertiary">
                  {' '}
                  ({skills.length})
                </span>
              )}
            </h3>
            <p className="text-caption text-sentinel-text-secondary max-w-prose">
              Skills and agents are local instruction files your AI clients
              silently follow. Sentinel scans each one&apos;s content for
              poisoning, instruction smuggling and line-jumping.
              {flaggedTotal > 0 && (
                <>
                  {' '}
                  <span className="text-sentinel-critical font-medium">
                    {flaggedTotal} risky skill
                    {flaggedTotal === 1 ? '' : 's'} flagged.
                  </span>
                </>
              )}
            </p>
          </div>
        </div>
      </div>

      {/* Body */}
      {error ? (
        <div
          className="rounded-lg border border-sentinel-critical-border bg-sentinel-critical-bg px-4 py-3 text-caption text-sentinel-critical"
          role="alert"
        >
          Skills scan failed: {error instanceof Error ? error.message : String(error)}
        </div>
      ) : !data && isValidating ? (
        <div className="flex items-center justify-center gap-2 py-8 text-caption text-sentinel-text-secondary">
          <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
          Scanning skills…
        </div>
      ) : skills.length === 0 ? (
        <div className="rounded-lg border border-dashed border-sentinel-border py-8 text-center text-caption text-sentinel-text-tertiary">
          No skills discovered on this Mac.
        </div>
      ) : (
        <div className="flex flex-col gap-6">
          {/* Reassurance banner when everything is clean. */}
          {flaggedTotal === 0 && (
            <div className="flex items-center gap-2 rounded-lg border border-sentinel-ok-border bg-sentinel-ok-bg px-4 py-3 text-caption text-sentinel-ok">
              <ShieldCheck className="h-4 w-4 shrink-0" aria-hidden />
              No risky skills — all {skills.length} discovered skill
              {skills.length === 1 ? '' : 's'} look clean.
            </div>
          )}

          {groups.map((g) => (
            <div key={g.client} className="flex flex-col gap-2">
              <div className="flex items-center gap-2">
                <span className="section-heading">{g.label}</span>
                <span className="text-caption text-sentinel-text-tertiary tabular-nums">
                  {g.skills.length} skill{g.skills.length === 1 ? '' : 's'}
                </span>
                {g.flaggedCount > 0 && (
                  <span className="badge badge-critical tabular-nums">
                    <AlertTriangle className="h-3 w-3" aria-hidden />
                    {g.flaggedCount} flagged
                  </span>
                )}
              </div>
              <div className="flex flex-col gap-2">
                {g.skills.map((s) => (
                  <SkillCard key={`${s.client}:${s.path}`} skill={s} />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
