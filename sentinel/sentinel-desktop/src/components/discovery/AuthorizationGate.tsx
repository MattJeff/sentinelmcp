// AuthorizationGate — first-launch dialog for the Discovery page.
// Asks for explicit consent before Sentinel reads any AI-client config
// file on the user's Mac. Frosted-glass modal, WWDC26 style.

import * as Dialog from '@radix-ui/react-dialog';
import { FileText, Lock, ShieldCheck, X } from 'lucide-react';

import { useDiscoveryAuth } from '@/hooks/useDiscoveryAuth';

/** Paths Sentinel will read. Surfaced verbatim so the user sees the scope. */
const INSPECTED_PATHS: ReadonlyArray<string> = [
  '~/Library/Application Support/Claude/claude_desktop_config.json',
  '~/.claude.json',
  '~/.cursor/mcp.json',
  '~/.codeium/windsurf/mcp_config.json',
  '~/.continue/config.yaml',
  '~/.config/zed/settings.json',
  '~/Library/Application Support/Code/User/settings.json',
  '~/.aider.conf.yml',
  '~/.config/goose/config.yaml',
  '~/.codex/config.toml',
  '~/Library/Application Support/Antigravity/User/settings.json',
  '~/.lmstudio/mcp.json',
];

export interface AuthorizationGateProps {
  /** Controlled open state. Should be `!authorized` from `useDiscoveryAuth`. */
  open: boolean;
  /** Called when the user cancels. Caller decides whether to navigate away. */
  onCancel?: () => void;
}

export default function AuthorizationGate({ open, onCancel }: AuthorizationGateProps) {
  const { allowOnce, allowAlways } = useDiscoveryAuth();

  return (
    <Dialog.Root
      open={open}
      onOpenChange={(next) => {
        if (!next) onCancel?.();
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/50 backdrop-blur-xs data-[state=open]:animate-fade-up" />
        <Dialog.Content
          className="surface-raised fixed left-1/2 top-1/2 z-50 w-[min(560px,92vw)] -translate-x-1/2 -translate-y-1/2 rounded-xl p-8 data-[state=open]:animate-fade-up shadow-overlay"
        >
          <div className="flex items-start gap-4">
            <div className="h-10 w-10 shrink-0 rounded-lg bg-sentinel-accent-dim border border-sentinel-border flex items-center justify-center">
              <ShieldCheck className="h-5 w-5 text-sentinel-accent" aria-hidden />
            </div>
            <div className="flex-1 min-w-0">
              <Dialog.Title className="text-title">
                Allow Sentinel to discover your AI clients?
              </Dialog.Title>
              <Dialog.Description className="mt-2 text-body leading-relaxed text-sentinel-text-secondary">
                Sentinel will read configuration files of AI clients installed on
                this Mac (Claude Desktop, Claude Code, Cursor, Windsurf, …) to
                surface their MCP servers.
              </Dialog.Description>
              <div className="mt-3 badge badge-ok">
                <Lock className="h-3 w-3" aria-hidden />
                Nothing leaves your Mac
              </div>
            </div>
            <Dialog.Close
              className="no-drag -mr-2 -mt-2 rounded-full p-2 text-sentinel-text-tertiary hover:bg-sentinel-raised hover:text-sentinel-text-primary transition-colors duration-150 focus-visible:outline-none focus-visible:shadow-focus"
              aria-label="Cancel"
              onClick={() => onCancel?.()}
            >
              <X className="h-4 w-4" aria-hidden />
            </Dialog.Close>
          </div>

          {/* Paths list */}
          <div className="section-heading mt-6 mb-2 flex items-center gap-2">
            <FileText className="h-3 w-3" aria-hidden />
            Files Sentinel will read
          </div>
          <div className="glass-soft max-h-[200px] overflow-auto rounded-lg p-4">
            <ul className="flex flex-col gap-1">
              {INSPECTED_PATHS.map((p) => (
                <li
                  key={p}
                  className="font-mono text-caption text-sentinel-text-secondary leading-relaxed truncate"
                  title={p}
                >
                  {p}
                </li>
              ))}
            </ul>
          </div>

          {/* Actions */}
          <div className="mt-8 flex items-center justify-end gap-2">
            <button
              type="button"
              className="btn"
              onClick={() => onCancel?.()}
            >
              Cancel
            </button>
            <button
              type="button"
              className="btn"
              onClick={() => allowOnce()}
            >
              Allow once
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => allowAlways()}
            >
              Allow always
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
