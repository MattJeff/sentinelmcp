// Filter bar for the Inventory page — sticky at the top.
// Implemented by Agent UI-2.

import clsx from 'clsx';
import { Search } from 'lucide-react';
import type { ServerStatus, SeverityColor, Transport } from '../api/contract';

export type ColorFilter = 'all' | SeverityColor;
export type TransportFilter = 'all' | Transport;
export type StatusFilter = 'all' | 'approved' | 'unknown' | 'suspect' | 'blocked';

export interface FilterBarProps {
  query: string;
  onQueryChange: (q: string) => void;
  color: ColorFilter;
  onColorChange: (c: ColorFilter) => void;
  transport: TransportFilter;
  onTransportChange: (t: TransportFilter) => void;
  status: StatusFilter;
  onStatusChange: (s: StatusFilter) => void;
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

export default function FilterBar({
  query,
  onQueryChange,
  color,
  onColorChange,
  transport,
  onTransportChange,
  status,
  onStatusChange,
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
        </div>
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
