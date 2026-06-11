// Filter bar for the Inventory page — sticky at the top.
// Implemented by Agent UI-2.

import { useEffect, useRef, useState } from 'react';
import clsx from 'clsx';
import {
  Search,
  Tag as TagIcon,
  FolderTree,
  ChevronDown,
  X,
} from 'lucide-react';
import type { ServerStatus, SeverityColor, Transport } from '../api/contract';
import { basename, type ScopeFilter } from '../lib/scope';

export type ColorFilter = 'all' | SeverityColor;
export type TransportFilter = 'all' | Transport;
export type StatusFilter = 'all' | 'approved' | 'unknown' | 'suspect' | 'blocked';
export type { ScopeFilter };

export interface FilterBarProps {
  query: string;
  onQueryChange: (q: string) => void;
  color: ColorFilter;
  onColorChange: (c: ColorFilter) => void;
  transport: TransportFilter;
  onTransportChange: (t: TransportFilter) => void;
  status: StatusFilter;
  onStatusChange: (s: StatusFilter) => void;
  /** Operator-curated tags currently used to narrow the inventory. */
  selectedTags?: string[];
  onSelectedTagsChange?: (tags: string[]) => void;
  /** Universe of tags exposed in the dropdown (typically `api.serverListTags()`). */
  availableTags?: string[];
  /** User/project/all scope bucket selector. */
  scope?: ScopeFilter;
  onScopeChange?: (s: ScopeFilter) => void;
  /** Distinct project paths observed in the current inventory. */
  availableProjectPaths?: string[];
  /** Currently-selected subset of project paths (empty = all projects). */
  selectedProjectPaths?: string[];
  onSelectedProjectPathsChange?: (paths: string[]) => void;
  visibleCount: number;
}

const COLOR_OPTIONS: { value: ColorFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'green', label: 'Green' },
  { value: 'orange', label: 'Orange' },
  { value: 'red', label: 'Red' },
];

const TRANSPORT_OPTIONS: { value: TransportFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'stdio', label: 'stdio' },
  { value: 'http', label: 'http' },
];

const STATUS_OPTIONS: { value: StatusFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'approved', label: 'Approved' },
  { value: 'unknown', label: 'Unknown' },
  { value: 'suspect', label: 'Suspect' },
  { value: 'blocked', label: 'Blocked' },
];

const SCOPE_OPTIONS: { value: ScopeFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'user', label: 'User' },
  { value: 'project', label: 'Project' },
];

export default function FilterBar({
  query,
  onQueryChange,
  color,
  onColorChange,
  transport,
  onTransportChange,
  status,
  onStatusChange,
  selectedTags = [],
  onSelectedTagsChange,
  availableTags = [],
  scope = 'all',
  onScopeChange,
  availableProjectPaths = [],
  selectedProjectPaths = [],
  onSelectedProjectPathsChange,
  visibleCount,
}: FilterBarProps) {
  return (
    <div className="sticky top-0 z-10 -mx-6 px-6 pb-4 pt-1 mb-4 bg-gradient-to-b from-black/30 to-transparent backdrop-blur-sm">
      <div className="glass rounded-glass p-4 flex flex-col gap-3">
        {/* Search + count */}
        <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3">
          <div className="relative flex-1 w-full">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-sentinel-text-tertiary" />
            <input
              className="input pl-9 text-[13px] w-full"
              placeholder="Search by endpoint, transport, scope…"
              value={query}
              onChange={(e) => onQueryChange(e.target.value)}
            />
          </div>
          <div className="text-[12px] text-sentinel-text-tertiary shrink-0 tabular-nums">
            {visibleCount} {visibleCount === 1 ? 'server' : 'servers'}
          </div>
        </div>

        {/* Filter rows — horizontal scroll on mobile, wrapping on sm+ */}
        <div className="flex sm:flex-wrap items-center gap-x-6 gap-y-2 overflow-x-auto sm:overflow-visible -mx-1 px-1 sm:mx-0 sm:px-0">
          <FilterGroup
            label="Color"
            options={COLOR_OPTIONS}
            value={color}
            onChange={onColorChange}
            getPillClass={(v) =>
              v === 'green'
                ? 'pill-green'
                : v === 'orange'
                  ? 'pill-orange'
                  : v === 'red'
                    ? 'pill-red'
                    : 'pill-blue'
            }
          />
          <FilterGroup
            label="Transport"
            options={TRANSPORT_OPTIONS}
            value={transport}
            onChange={onTransportChange}
            getPillClass={() => 'pill-blue'}
          />
          <FilterGroup
            label="Status"
            options={STATUS_OPTIONS}
            value={status}
            onChange={onStatusChange}
            getPillClass={(v) =>
              v === 'approved'
                ? 'pill-green'
                : v === 'unknown'
                  ? 'pill-orange'
                  : v === 'suspect' || v === 'blocked'
                    ? 'pill-red'
                    : 'pill-blue'
            }
          />
          {onScopeChange && (
            <FilterGroup
              label="Scope"
              options={SCOPE_OPTIONS}
              value={scope}
              onChange={onScopeChange}
              getPillClass={(v) =>
                v === 'project'
                  ? 'bg-teal-500/15 text-teal-100 border border-teal-400/30'
                  : v === 'user'
                    ? 'bg-white/10 text-sentinel-text-primary border border-white/15'
                    : 'pill-blue'
              }
            />
          )}
          {onScopeChange &&
            scope === 'project' &&
            onSelectedProjectPathsChange && (
              <ProjectPathFilter
                available={availableProjectPaths}
                selected={selectedProjectPaths}
                onChange={onSelectedProjectPathsChange}
              />
            )}
          {onSelectedTagsChange && (
            <TagsFilter
              available={availableTags}
              selected={selectedTags}
              onChange={onSelectedTagsChange}
            />
          )}
        </div>
      </div>
    </div>
  );
}

interface TagsFilterProps {
  available: string[];
  selected: string[];
  onChange: (next: string[]) => void;
}

function TagsFilter({ available, selected, onChange }: TagsFilterProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const rootRef = useRef<HTMLDivElement | null>(null);

  // Close on outside click so the popover doesn't trap focus.
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const toggleTag = (tag: string) => {
    if (selected.includes(tag)) {
      onChange(selected.filter((t) => t !== tag));
    } else {
      onChange([...selected, tag]);
    }
  };

  const q = query.trim().toLowerCase();
  const filtered = q
    ? available.filter((t) => t.includes(q))
    : available;

  // Show selected-but-unknown tags too so the operator can always clear them.
  const orphans = selected.filter((t) => !available.includes(t));

  return (
    <div className="flex items-center gap-2 shrink-0">
      <span className="section-heading shrink-0">Tags</span>
      <div className="relative" ref={rootRef}>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className={clsx(
            'pill inline-flex items-center gap-1.5 transition-all',
            selected.length > 0
              ? 'bg-blue-500/15 text-blue-200 border border-blue-400/30'
              : 'text-sentinel-text-secondary bg-white/4 border border-white/10 hover:bg-white/8 hover:text-white',
          )}
          aria-haspopup="listbox"
          aria-expanded={open}
          title={
            selected.length === 0
              ? 'Filter by tags'
              : `Filter by tags: ${selected.join(', ')}`
          }
        >
          <TagIcon size={11} aria-hidden />
          {selected.length === 0
            ? 'All'
            : `${selected.length} selected`}
          <ChevronDown size={11} aria-hidden />
        </button>
        {selected.length > 0 && (
          <button
            type="button"
            onClick={() => onChange([])}
            className="ml-1.5 inline-flex items-center justify-center rounded-full p-0.5 text-sentinel-text-tertiary hover:text-white hover:bg-white/10"
            aria-label="Clear tag filter"
            title="Clear tag filter"
          >
            <X size={11} />
          </button>
        )}
        {open && (
          <div
            role="listbox"
            aria-multiselectable
            className="absolute left-0 top-full mt-1 z-20 w-64 rounded-md border border-white/10 bg-slate-900/95 backdrop-blur shadow-lg p-2 flex flex-col gap-1.5"
          >
            <input
              autoFocus
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search tags…"
              className="w-full rounded bg-white/5 border border-white/10 px-2 py-1 text-[12px] text-sentinel-text-primary placeholder:text-sentinel-text-tertiary outline-none focus:border-blue-400/40"
            />
            <div className="max-h-56 overflow-y-auto flex flex-col">
              {filtered.length === 0 && orphans.length === 0 ? (
                <div className="px-2 py-2 text-[11px] text-sentinel-text-tertiary">
                  No tags found.
                </div>
              ) : (
                <>
                  {filtered.map((tag) => {
                    const active = selected.includes(tag);
                    return (
                      <label
                        key={tag}
                        className="flex items-center gap-2 px-2 py-1 rounded hover:bg-white/5 cursor-pointer text-[12px] text-sentinel-text-secondary"
                      >
                        <input
                          type="checkbox"
                          checked={active}
                          onChange={() => toggleTag(tag)}
                          className="accent-blue-400"
                        />
                        <span className={active ? 'text-white' : ''}>{tag}</span>
                      </label>
                    );
                  })}
                  {orphans.map((tag) => (
                    <label
                      key={`orphan-${tag}`}
                      className="flex items-center gap-2 px-2 py-1 rounded hover:bg-white/5 cursor-pointer text-[12px] text-sentinel-text-tertiary italic"
                      title="Selected but no longer present in any server"
                    >
                      <input
                        type="checkbox"
                        checked
                        onChange={() => toggleTag(tag)}
                        className="accent-blue-400"
                      />
                      <span>{tag}</span>
                    </label>
                  ))}
                </>
              )}
            </div>
            <div className="flex items-center justify-between border-t border-white/10 pt-1.5 text-[11px]">
              <span className="text-sentinel-text-tertiary">
                Match all selected
              </span>
              <button
                type="button"
                onClick={() => onChange([])}
                disabled={selected.length === 0}
                className="text-sentinel-blue-glow hover:underline disabled:opacity-50 disabled:no-underline"
              >
                Clear
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

interface ProjectPathFilterProps {
  available: string[];
  selected: string[];
  onChange: (next: string[]) => void;
}

function ProjectPathFilter({
  available,
  selected,
  onChange,
}: ProjectPathFilterProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const rootRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const togglePath = (path: string) => {
    if (selected.includes(path)) {
      onChange(selected.filter((p) => p !== path));
    } else {
      onChange([...selected, path]);
    }
  };

  const q = query.trim().toLowerCase();
  const filtered = q
    ? available.filter((p) => p.toLowerCase().includes(q))
    : available;

  // Show selected-but-no-longer-present paths so the operator can clear them.
  const orphans = selected.filter((p) => !available.includes(p));

  const buttonLabel =
    selected.length === 0
      ? 'All projects'
      : `${selected.length} selected`;

  return (
    <div className="flex items-center gap-2 shrink-0">
      <span className="section-heading shrink-0">Project path</span>
      <div className="relative" ref={rootRef}>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className={clsx(
            'pill inline-flex items-center gap-1.5 transition-all',
            selected.length > 0
              ? 'bg-teal-500/15 text-teal-100 border border-teal-400/30'
              : 'text-sentinel-text-secondary bg-white/4 border border-white/10 hover:bg-white/8 hover:text-white',
          )}
          aria-haspopup="listbox"
          aria-expanded={open}
          title={
            selected.length === 0
              ? 'Filter by project path'
              : `Filter by project path: ${selected.join(', ')}`
          }
        >
          <FolderTree size={11} aria-hidden />
          {buttonLabel}
          <ChevronDown size={11} aria-hidden />
        </button>
        {selected.length > 0 && (
          <button
            type="button"
            onClick={() => onChange([])}
            className="ml-1.5 inline-flex items-center justify-center rounded-full p-0.5 text-sentinel-text-tertiary hover:text-white hover:bg-white/10"
            aria-label="Clear project path filter"
            title="Clear project path filter"
          >
            <X size={11} />
          </button>
        )}
        {open && (
          <div
            role="listbox"
            aria-multiselectable
            className="absolute left-0 top-full mt-1 z-20 w-80 rounded-md border border-white/10 bg-slate-900/95 backdrop-blur shadow-lg p-2 flex flex-col gap-1.5"
          >
            <input
              autoFocus
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search project paths…"
              className="w-full rounded bg-white/5 border border-white/10 px-2 py-1 text-[12px] text-sentinel-text-primary placeholder:text-sentinel-text-tertiary outline-none focus:border-teal-400/40"
            />
            <div className="max-h-56 overflow-y-auto flex flex-col">
              {filtered.length === 0 && orphans.length === 0 ? (
                <div className="px-2 py-2 text-[11px] text-sentinel-text-tertiary">
                  No project paths in the current inventory.
                </div>
              ) : (
                <>
                  {filtered.map((path) => {
                    const active = selected.includes(path);
                    return (
                      <label
                        key={path}
                        className="flex items-center gap-2 px-2 py-1 rounded hover:bg-white/5 cursor-pointer text-[12px] text-sentinel-text-secondary"
                        title={path}
                      >
                        <input
                          type="checkbox"
                          checked={active}
                          onChange={() => togglePath(path)}
                          className="accent-teal-400"
                        />
                        <span
                          className={clsx(
                            'truncate flex-1 min-w-0',
                            active && 'text-white',
                          )}
                        >
                          <span className="text-sentinel-text-primary">
                            {basename(path) || path}
                          </span>
                          <span className="ml-1.5 text-sentinel-text-tertiary text-[10px]">
                            {path}
                          </span>
                        </span>
                      </label>
                    );
                  })}
                  {orphans.map((path) => (
                    <label
                      key={`orphan-${path}`}
                      className="flex items-center gap-2 px-2 py-1 rounded hover:bg-white/5 cursor-pointer text-[12px] text-sentinel-text-tertiary italic"
                      title={`Selected but no longer present: ${path}`}
                    >
                      <input
                        type="checkbox"
                        checked
                        onChange={() => togglePath(path)}
                        className="accent-teal-400"
                      />
                      <span className="truncate">{path}</span>
                    </label>
                  ))}
                </>
              )}
            </div>
            <div className="flex items-center justify-between border-t border-white/10 pt-1.5 text-[11px]">
              <span className="text-sentinel-text-tertiary">
                Match any selected
              </span>
              <button
                type="button"
                onClick={() => onChange([])}
                disabled={selected.length === 0}
                className="text-sentinel-blue-glow hover:underline disabled:opacity-50 disabled:no-underline"
              >
                Clear
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

interface FilterGroupProps<T extends string> {
  label: string;
  options: { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
  getPillClass: (v: T) => string;
}

function FilterGroup<T extends string>({
  label,
  options,
  value,
  onChange,
  getPillClass,
}: FilterGroupProps<T>) {
  return (
    <div className="flex items-center gap-2 shrink-0">
      <span className="section-heading shrink-0">{label}</span>
      <div className="flex sm:flex-wrap items-center gap-1.5">
        {options.map((opt) => {
          const active = opt.value === value;
          return (
            <button
              key={opt.value}
              type="button"
              onClick={() => onChange(opt.value)}
              className={clsx(
                'pill transition-all shrink-0',
                active
                  ? getPillClass(opt.value)
                  : 'text-sentinel-text-secondary bg-white/4 border border-white/10 hover:bg-white/8 hover:text-white',
              )}
            >
              {opt.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}
