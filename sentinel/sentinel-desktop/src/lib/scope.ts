// Helpers for the per-server visibility scope (`ScopeServeur` in the API
// contract). Centralised here so the badge on `ServerCard`, the filter in
// the `FilterBar`, and the metadata row in `ServerDetailDrawer` all agree
// on the same labelling rules.

import type { ScopeServeur } from '../api/contract';

/**
 * Return just the trailing path segment of a POSIX-style absolute path,
 * matching the JS equivalent of `basename(3)`. Trailing slashes are
 * trimmed first so `"/Users/foo/Desktop/myproj/"` still resolves to
 * `"myproj"`.
 */
export function basename(path: string): string {
  if (!path) return '';
  let p = path;
  while (p.length > 1 && (p.endsWith('/') || p.endsWith('\\'))) {
    p = p.slice(0, -1);
  }
  const slash = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return slash === -1 ? p : p.slice(slash + 1);
}

/**
 * Short human-readable label for a scope, suitable for badges and pills.
 * `undefined` means "no scope known" and renders as an empty string so
 * callers can choose to skip rendering altogether.
 */
export function scopeLabel(scope: ScopeServeur | undefined | null): string {
  if (!scope) return '';
  if (scope.kind === 'user') return 'user';
  const base = basename(scope.path);
  return `project: ${base || scope.path}`;
}

/**
 * Long tooltip-style label used by the drawer and the badge `title=`. For
 * project scopes this exposes the full path so the operator can copy it.
 */
export function scopeTooltip(scope: ScopeServeur | undefined | null): string {
  if (!scope) return '';
  if (scope.kind === 'user') return 'Declared globally for this macOS user';
  return scope.path;
}

/** Three-way bucket the filter bar exposes to the inventory page. */
export type ScopeFilter = 'all' | 'user' | 'project';

/**
 * Return `true` when `scope` belongs to the selected bucket. A missing
 * scope is treated as `{ kind: 'user' }` so legacy backends keep working.
 */
export function matchesScopeFilter(
  scope: ScopeServeur | undefined | null,
  filter: ScopeFilter,
): boolean {
  if (filter === 'all') return true;
  const kind = scope?.kind ?? 'user';
  return kind === filter;
}
