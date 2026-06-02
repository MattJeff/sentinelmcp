// Glass-style WWDC26 dashboard layout — implemented by Agent UI.2
// (foundation by bootstrap, refined by sub-agents).
//
// Layout = aurora bg + frosted titlebar + frosted sidebar + frosted main.
//
// Responsive behavior (Agent R1):
//   ≥ lg (1024 px)  → sidebar expanded (240 px) or collapsed rail (64 px)
//                     toggled by chevron button; user preference persisted.
//   < lg, ≥ md      → sidebar forced to icon-only rail (64 px).
//   < md (768 px)   → sidebar becomes a slide-in drawer, opened via a
//                     hamburger button in the main titlebar; tapping the
//                     backdrop closes it.

import { useState } from 'react';
import useSWR from 'swr';
import {
  Activity,
  AlertCircle,
  BarChart3,
  CheckSquare,
  ChevronLeft,
  ChevronRight,
  Clock,
  FileText,
  LayoutGrid,
  Menu,
  Network,
  Search,
  Settings as SettingsIcon,
  ShieldCheck,
  Telescope,
  X,
} from 'lucide-react';
import clsx from 'clsx';
import * as Tooltip from '@radix-ui/react-tooltip';

import { api } from '../api/tauri';
import { COMMANDS, type LiveStatus } from '../api/contract';
import { useSidebar } from '../hooks/useSidebar';

import OverviewPage from '../pages/OverviewPage';
import InventoryPage from '../pages/InventoryPage';
import AlertsPage from '../pages/AlertsPage';
import ReportPage from '../pages/ReportPage';
import CompliancePage from '../pages/CompliancePage';
import ScanPage from '../pages/ScanPage';
import ApprovalsPage from '../pages/ApprovalsPage';
import SettingsPage from '../pages/SettingsPage';
import TimelinePage from '../pages/TimelinePage';
import TrustGraphPage from '../pages/TrustGraphPage';
import DiscoveryPage from '../pages/DiscoveryPage';

export type NavId =
  | 'overview'
  | 'inventory'
  | 'discovery'
  | 'scan'
  | 'alerts'
  | 'approvals'
  | 'trust-graph'
  | 'timeline'
  | 'compliance'
  | 'report'
  | 'settings';

interface NavItem {
  id: NavId;
  label: string;
  icon: typeof LayoutGrid;
  badge?: string;
}

const NAV: NavItem[] = [
  { id: 'overview', label: 'Overview', icon: LayoutGrid },
  { id: 'inventory', label: 'Inventory', icon: ShieldCheck },
  { id: 'discovery', label: 'Discovery', icon: Telescope },
  { id: 'scan', label: 'Live Scan', icon: Activity },
  { id: 'alerts', label: 'Alerts', icon: AlertCircle },
  { id: 'approvals', label: 'Approvals', icon: CheckSquare },
  { id: 'trust-graph', label: 'Trust graph', icon: Network },
  { id: 'timeline', label: 'Time travel', icon: Clock },
  { id: 'compliance', label: 'Compliance', icon: BarChart3 },
  { id: 'report', label: 'Report', icon: FileText },
  { id: 'settings', label: 'Settings', icon: SettingsIcon },
];

export interface DashboardLayoutProps {
  active?: NavId;
  onActiveChange?: (id: NavId) => void;
  onOpenCommandPalette?: () => void;
}

export default function DashboardLayout({
  active: activeProp,
  onActiveChange,
  onOpenCommandPalette,
}: DashboardLayoutProps = {}) {
  // Support controlled and uncontrolled usage so the layout still renders
  // standalone (Storybook, tests) without props.
  const [internalActive, setInternalActive] = useState<NavId>('overview');
  const active = activeProp ?? internalActive;
  const setActive = (id: NavId) => {
    if (onActiveChange) onActiveChange(id);
    else setInternalActive(id);
    // Close the mobile drawer after navigation so the user sees the new page.
    setMobileOpen(false);
  };

  const { collapsed, setCollapsed, mobileOpen, setMobileOpen } = useSidebar();

  const isMac =
    typeof navigator !== 'undefined' &&
    /Mac|iPhone|iPad|iPod/.test(navigator.platform);
  const shortcutLabel = isMac ? '⌘K' : 'Ctrl K';

  return (
    <Tooltip.Provider delayDuration={150} skipDelayDuration={300}>
      <div className="app-bg flex h-full text-sentinel-text-primary">
        {/* Mobile drawer backdrop (< md only). */}
        {mobileOpen && (
          <button
            type="button"
            aria-label="Close navigation"
            onClick={() => setMobileOpen(false)}
            className="md:hidden fixed inset-0 z-30 bg-black/50 backdrop-blur-sm animate-fade-in"
          />
        )}

        {/* Sidebar.
            - < md: fixed slide-in drawer (240 px) controlled by `mobileOpen`.
            - md … lg: in-flow icon-only rail (64 px), `collapsed` forced true.
            - ≥ lg: in-flow, width follows `collapsed`.                */}
        <Sidebar
          active={active}
          setActive={setActive}
          collapsed={collapsed}
          setCollapsed={setCollapsed}
          mobileOpen={mobileOpen}
          setMobileOpen={setMobileOpen}
          onOpenCommandPalette={onOpenCommandPalette}
          shortcutLabel={shortcutLabel}
        />

        {/* Main */}
        <main className="flex-1 min-w-0 p-3 md:pl-0 overflow-hidden flex flex-col">
          <div className="glass-strong rounded-glass flex-1 overflow-hidden flex flex-col">
            {/* Titlebar */}
            <div className="titlebar flex items-center justify-between px-4 sm:px-6 py-3.5 border-b border-white/8 gap-3">
              <div className="no-drag flex items-center gap-2 min-w-0">
                {/* Hamburger — only < md. */}
                <button
                  type="button"
                  onClick={() => setMobileOpen(true)}
                  aria-label="Open navigation"
                  className="md:hidden inline-flex items-center justify-center h-8 w-8 rounded-lg hover:bg-white/8 text-sentinel-text-secondary hover:text-white transition-colors"
                >
                  <Menu className="h-4 w-4" />
                </button>
                <div className="min-w-0">
                  <h1 className="text-[15px] font-semibold tracking-tight truncate">
                    {NAV.find((n) => n.id === active)?.label}
                  </h1>
                  <div className="text-[11px] text-sentinel-text-tertiary mt-0.5 truncate">
                    {labelSubtitle(active)}
                  </div>
                </div>
              </div>
              <div className="no-drag flex items-center gap-2 shrink-0">
                <span className="pill pill-green">
                  <span className="dot dot-green" /> Monitoring
                </span>
              </div>
            </div>

            {/* Page content */}
            <div className="flex-1 overflow-auto p-4 sm:p-6 animate-fade-up">
              {active === 'overview' && <OverviewPage />}
              {active === 'inventory' && <InventoryPage />}
              {active === 'discovery' && <DiscoveryPage />}
              {active === 'scan' && <ScanPage />}
              {active === 'alerts' && <AlertsPage />}
              {active === 'approvals' && <ApprovalsPage />}
              {active === 'trust-graph' && <TrustGraphPage />}
              {active === 'timeline' && <TimelinePage />}
              {active === 'compliance' && <CompliancePage />}
              {active === 'report' && <ReportPage />}
              {active === 'settings' && <SettingsPage />}
            </div>
          </div>
        </main>
      </div>
    </Tooltip.Provider>
  );
}

/* ──────────────────────────────────────────────────────────────────────────
 * Sidebar
 *
 * Renders three visual states from one tree, switched purely with Tailwind
 * responsive utilities so behavior is correct without JS-driven resize logic:
 *
 *   - mobile drawer  (< md): position:fixed, translated off-screen unless
 *                            `mobileOpen` is true.
 *   - icon rail      (md … lg, or `collapsed` at ≥ lg): width 64 px,
 *                            labels hidden, tooltips on hover.
 *   - expanded       (≥ lg && !collapsed): width 240 px, full labels.
 * ────────────────────────────────────────────────────────────────────────── */
interface SidebarProps {
  active: NavId;
  setActive: (id: NavId) => void;
  collapsed: boolean;
  setCollapsed: (next: boolean | ((prev: boolean) => boolean)) => void;
  mobileOpen: boolean;
  setMobileOpen: (next: boolean | ((prev: boolean) => boolean)) => void;
  onOpenCommandPalette?: () => void;
  shortcutLabel: string;
}

function Sidebar({
  active,
  setActive,
  collapsed,
  setCollapsed,
  mobileOpen,
  setMobileOpen,
  onOpenCommandPalette,
  shortcutLabel,
}: SidebarProps) {
  // `compact` = icon-only rail. True when explicitly collapsed at ≥lg, OR
  // whenever we're below `lg` (we override classes with `lg:` variants
  // further down so that the icon-only treatment is always applied below lg
  // regardless of the user's stored preference).
  const compact = collapsed;

  return (
    <aside
      className={clsx(
        // Mobile drawer base styles (apply < md).
        'fixed inset-y-0 left-0 z-40 p-3 transition-transform duration-200 ease-out',
        mobileOpen ? 'translate-x-0' : '-translate-x-full',
        // ≥ md: in-flow, never translated off-screen.
        'md:static md:translate-x-0 md:transition-[width] md:duration-200',
        // Width logic:
        //   < md drawer: fixed 240 px so it always feels usable.
        //   md … lg:    forced 64 px icon rail.
        //   ≥ lg:        follows `collapsed`.
        'w-[240px] shrink-0',
        'md:w-[64px]',
        compact ? 'lg:w-[64px]' : 'lg:w-[240px]',
      )}
      aria-label="Primary navigation"
    >
      <div className="glass-strong h-full rounded-glass p-3 flex flex-col gap-1">
        {/* Header: brand + close-on-mobile button. */}
        <div className="titlebar px-1 pt-1 pb-3 flex items-center gap-2">
          <div className="flex items-center gap-2.5 no-drag min-w-0 flex-1">
            <div className="h-7 w-7 shrink-0 rounded-lg bg-gradient-to-br from-sentinel-blue to-sentinel-purple shadow-glow-blue flex items-center justify-center">
              <ShieldCheck className="h-4 w-4 text-white" />
            </div>
            {/* Brand text: hidden when compact at ≥lg, hidden md…lg,
                but always shown on the < md drawer. */}
            <div
              className={clsx(
                'flex-1 min-w-0',
                'md:hidden',
                compact ? 'lg:hidden' : 'lg:block',
              )}
            >
              <div className="text-[13px] font-semibold leading-tight truncate">
                Sentinel MCP
              </div>
              <div className="text-[10px] text-sentinel-text-tertiary leading-tight flex items-center gap-1.5">
                <span>v0.2.1</span>
                <LiveBadge compact={false} />
              </div>
            </div>
            {/* Compact LiveBadge dot — shown md…lg, and ≥lg when compact. */}
            <div
              className={clsx(
                'hidden',
                'md:flex',
                compact ? 'lg:flex' : 'lg:hidden',
                'items-center justify-center',
              )}
            >
              <LiveBadge compact />
            </div>
          </div>

          {/* Mobile drawer close button (< md only). */}
          <button
            type="button"
            onClick={() => setMobileOpen(false)}
            aria-label="Close navigation"
            className="md:hidden inline-flex items-center justify-center h-7 w-7 rounded-lg hover:bg-white/8 text-sentinel-text-secondary hover:text-white transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Command palette trigger.
            Expanded: full search input. Compact: icon-only square button. */}
        <div className="no-drag mb-2">
          {/* Expanded variant — shown on < md drawer, and ≥ lg when not compact. */}
          <button
            type="button"
            onClick={() => onOpenCommandPalette?.()}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onOpenCommandPalette?.();
              }
            }}
            className={clsx(
              'group relative w-full text-left',
              'md:hidden',
              compact ? 'lg:hidden' : 'lg:block',
            )}
            aria-label="Open command palette"
          >
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-sentinel-text-tertiary" />
            <span className="input flex items-center pl-8 pr-14 text-[12px] text-sentinel-text-tertiary group-hover:text-sentinel-text-secondary transition-colors">
              Search servers, tools…
            </span>
            <kbd className="absolute right-2 top-1/2 -translate-y-1/2 inline-flex items-center gap-0.5 rounded border border-white/12 bg-white/5 px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-sentinel-text-tertiary">
              {shortcutLabel}
            </kbd>
          </button>

          {/* Compact variant — shown md…lg, and ≥lg when compact. */}
          <Tooltip.Root>
            <Tooltip.Trigger asChild>
              <button
                type="button"
                onClick={() => onOpenCommandPalette?.()}
                aria-label="Open command palette"
                className={clsx(
                  'hidden items-center justify-center w-full h-9 rounded-lg text-sentinel-text-secondary hover:bg-white/8 hover:text-white transition-colors',
                  'md:inline-flex',
                  compact ? 'lg:inline-flex' : 'lg:hidden',
                )}
              >
                <Search className="h-4 w-4" />
              </button>
            </Tooltip.Trigger>
            <TooltipContent>
              Search{' '}
              <kbd className="ml-1 rounded border border-white/15 bg-white/5 px-1 py-px text-[9px]">
                {shortcutLabel}
              </kbd>
            </TooltipContent>
          </Tooltip.Root>
        </div>

        {/* Section heading — hidden when compact (md…lg, and ≥lg if collapsed). */}
        <div
          className={clsx(
            'section-heading mt-2 mb-1 px-2',
            'md:hidden',
            compact ? 'lg:hidden' : 'lg:block',
          )}
        >
          Workspace
        </div>

        {/* Nav */}
        <nav className="no-drag flex flex-col gap-0.5 overflow-y-auto pr-0.5">
          {NAV.map((item) => {
            const Icon = item.icon;
            const isActive = active === item.id;
            return (
              <Tooltip.Root key={item.id}>
                <Tooltip.Trigger asChild>
                  <button
                    onClick={() => setActive(item.id)}
                    className={clsx(
                      'group flex items-center gap-2.5 rounded-lg text-[13px] text-left transition-all',
                      // Padding shrinks in compact: keep the icon centered in a
                      // square hit-target instead of left-padded row.
                      'px-3 py-2',
                      'md:px-0 md:py-2 md:justify-center',
                      compact
                        ? 'lg:px-0 lg:py-2 lg:justify-center'
                        : 'lg:px-3 lg:py-2 lg:justify-start',
                      isActive
                        ? 'bg-white/12 text-white shadow-glass-soft'
                        : 'text-sentinel-text-secondary hover:bg-white/6 hover:text-white',
                    )}
                    aria-label={item.label}
                    aria-current={isActive ? 'page' : undefined}
                  >
                    <Icon
                      className={clsx(
                        'h-4 w-4 shrink-0',
                        isActive ? 'text-sentinel-blue-glow' : 'opacity-80',
                      )}
                    />
                    {/* Label — hidden when compact. */}
                    <span
                      className={clsx(
                        'flex-1 truncate',
                        'md:hidden',
                        compact ? 'lg:hidden' : 'lg:inline',
                      )}
                    >
                      {item.label}
                    </span>
                    {item.badge && (
                      <span
                        className={clsx(
                          'pill pill-red text-[9px] px-1.5 py-0.5',
                          'md:hidden',
                          compact ? 'lg:hidden' : 'lg:inline-flex',
                        )}
                      >
                        {item.badge}
                      </span>
                    )}
                  </button>
                </Tooltip.Trigger>
                {/* Tooltip is only useful in compact mode; we still render it
                    always — Radix only shows on hover, and in expanded mode
                    the label is already visible so users won't hover-wait. */}
                <TooltipContent>
                  {item.label}
                  {item.badge ? ` · ${item.badge}` : ''}
                </TooltipContent>
              </Tooltip.Root>
            );
          })}
        </nav>

        {/* Footer: collapse toggle + meta. */}
        <div className="mt-auto pt-3 border-t border-white/8 flex flex-col gap-2">
          {/* Chevron toggle — only at ≥ lg, where the user can actually flip
              between expanded and rail. Hidden on the mobile drawer and on
              md…lg (where it is forced compact). */}
          <button
            type="button"
            onClick={() => setCollapsed((p) => !p)}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-pressed={collapsed}
            className={clsx(
              'hidden lg:inline-flex items-center gap-2 rounded-lg text-[11px] text-sentinel-text-secondary hover:bg-white/8 hover:text-white transition-colors',
              compact ? 'justify-center w-full h-8 px-0' : 'justify-end px-2 py-1.5',
            )}
          >
            {collapsed ? (
              <ChevronRight className="h-3.5 w-3.5" />
            ) : (
              <>
                <span>Collapse</span>
                <ChevronLeft className="h-3.5 w-3.5" />
              </>
            )}
          </button>

          {/* Meta line — hidden when compact. */}
          <div
            className={clsx(
              'text-[10px] text-sentinel-text-tertiary px-2',
              'md:hidden',
              compact ? 'lg:hidden' : 'lg:block',
            )}
          >
            Read-only · Local only
          </div>
        </div>
      </div>
    </aside>
  );
}

/** Small wrapper around Radix Tooltip's portal'd content with our glass look. */
function TooltipContent({ children }: { children: React.ReactNode }) {
  return (
    <Tooltip.Portal>
      <Tooltip.Content
        side="right"
        sideOffset={8}
        className="z-50 rounded-md bg-black/80 backdrop-blur px-2 py-1 text-[11px] text-white shadow-lg ring-1 ring-white/10 data-[state=delayed-open]:animate-fade-in"
      >
        {children}
        <Tooltip.Arrow className="fill-black/80" />
      </Tooltip.Content>
    </Tooltip.Portal>
  );
}

/**
 * "Live · 30 s" pulsing badge for the sidebar.
 *
 * Polls `get_live_status` every 5 s (cheap — just reads atomic state on the
 * Rust side) so the interval label + last-refresh tooltip stay fresh
 * without subscribing to events here.
 *
 * When `compact` is true, renders only the green pulsing dot — no text — so
 * it fits inside the 64 px icon-rail.
 */
function LiveBadge({ compact = false }: { compact?: boolean } = {}) {
  const { data } = useSWR<LiveStatus>(
    COMMANDS.getLiveStatus,
    () => api.getLiveStatus(),
    { refreshInterval: 5000, revalidateOnFocus: false },
  );

  const intervalSecs = data?.interval_secs ?? 30;
  const lastIso = data?.last_refresh_iso;
  const lastLabel = lastIso ? formatLastRefresh(lastIso) : '—';
  const ariaLabel = `Live monitoring active, ${intervalSecs} second interval, last refresh ${lastLabel}`;

  if (compact) {
    return (
      <span
        title={`Live · ${intervalSecs}s · last refresh ${lastLabel}`}
        aria-label={ariaLabel}
        className="relative inline-flex h-1.5 w-1.5"
      >
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400/70 opacity-75" />
        <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400" />
      </span>
    );
  }

  return (
    <span
      title={`Last refresh ${lastLabel}`}
      className="inline-flex items-center gap-1 rounded-full bg-emerald-400/10 px-1.5 py-[1px] text-[9px] font-medium text-emerald-300 ring-1 ring-emerald-400/20"
      aria-label={ariaLabel}
    >
      <span className="relative flex h-1.5 w-1.5">
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400/70 opacity-75" />
        <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400" />
      </span>
      Live · {intervalSecs}s
    </span>
  );
}

function formatLastRefresh(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

function labelSubtitle(id: NavId): string {
  switch (id) {
    case 'overview':
      return 'High-level picture of every MCP server your agents reach.';
    case 'inventory':
      return 'Every server, every tool, every fingerprint.';
    case 'discovery':
      return 'Every AI client on this Mac and the MCP servers it declares.';
    case 'scan':
      return 'Live capture of MCP traffic, filling the inventory in front of you.';
    case 'alerts':
      return 'Rug-pulls, poisoning, exfiltration — with the diff that triggered them.';
    case 'approvals':
      return 'Mark each server approved, to investigate, or blocked.';
    case 'trust-graph':
      return 'Who can reach what on this Mac — and how badly it bleeds if compromised.';
    case 'timeline':
      return 'Replay every JSON-RPC envelope Sentinel has captured on the wire.';
    case 'compliance':
      return 'OWASP MCP09 / MCP03 · SAFE-MCP T1001 / T1201 · SOC 2 · ISO 27001.';
    case 'report':
      return 'Signed bundle for your auditor — PDF + JSON, Ed25519-signed.';
    case 'settings':
      return 'Channels, retention, scan modes.';
  }
}
