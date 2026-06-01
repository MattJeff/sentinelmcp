// ToolList — accordion of MCP tools with description and JSON schema preview.
// Implemented by Agent UI-9.

import { useState } from 'react';
import clsx from 'clsx';
import { ChevronRight, AlertTriangle } from 'lucide-react';
import type { Tool } from '../api/contract';

export interface ToolListProps {
  tools: Tool[];
}

// Poisoning red-flags — substrings that, when seen in a tool description,
// strongly suggest a prompt-injection / poisoning attempt.
const POISONING_PATTERNS = ['[SYSTEM]', '.env', '~/.ssh', 'id_rsa'] as const;

function isPoisoningSuspect(description: string | null): boolean {
  if (!description) return false;
  const haystack = description;
  return POISONING_PATTERNS.some((needle) => haystack.includes(needle));
}

function formatJson(schema: unknown): string {
  try {
    return JSON.stringify(schema, null, 2);
  } catch {
    return String(schema);
  }
}

export default function ToolList({ tools }: ToolListProps) {
  const [open, setOpen] = useState<Record<string, boolean>>({});

  if (tools.length === 0) {
    return (
      <div className="text-[12px] text-sentinel-text-tertiary py-2">
        No tools advertised by this server.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      {tools.map((tool) => {
        const suspect = isPoisoningSuspect(tool.description);
        const isOpen = !!open[tool.name];
        return (
          <div
            key={tool.name}
            className={clsx(
              'glass-soft rounded-glass overflow-hidden',
              suspect && 'shadow-glow-red',
            )}
          >
            <button
              type="button"
              onClick={() =>
                setOpen((prev) => ({ ...prev, [tool.name]: !prev[tool.name] }))
              }
              className="no-drag w-full flex items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-white/[0.03]"
              aria-expanded={isOpen}
            >
              <ChevronRight
                size={14}
                className={clsx(
                  'shrink-0 transition-transform duration-200 text-sentinel-text-tertiary',
                  isOpen && 'rotate-90',
                )}
              />
              <div className="flex-1 min-w-0 flex items-center gap-2">
                <span className="font-mono text-[13px] font-semibold text-sentinel-text-primary truncate">
                  {tool.name}
                </span>
                {suspect && (
                  <span
                    className="pill pill-red shrink-0"
                    title="Description contains poisoning indicators"
                  >
                    <AlertTriangle size={11} />
                    Poisoning suspect
                  </span>
                )}
              </div>
            </button>
            {isOpen && (
              <div className="px-4 pb-4 pt-1 animate-fade-up flex flex-col gap-3">
                {tool.description && (
                  <p className="text-[12px] leading-relaxed text-sentinel-text-secondary whitespace-pre-wrap">
                    {tool.description}
                  </p>
                )}
                <div>
                  <div className="section-heading mb-1.5">Input schema</div>
                  <pre className="font-mono text-[11px] leading-relaxed text-sentinel-text-secondary bg-black/30 rounded-glass p-3 overflow-x-auto max-h-72">
                    {formatJson(tool.input_schema)}
                  </pre>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
