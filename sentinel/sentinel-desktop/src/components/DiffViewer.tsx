// DiffViewer — renders a unified/markdown diff with green/red/blue tints.
// Reusable across pages. Implemented by Agent UI-4 for the Alerts feed.

import { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import clsx from 'clsx';

export interface DiffViewerProps {
  diff: string;
}

type LineKind = 'add' | 'del' | 'hunk' | 'meta';

function classify(line: string): LineKind {
  if (line.startsWith('@@')) return 'hunk';
  if (line.startsWith('+++') || line.startsWith('---')) return 'meta';
  if (line.startsWith('+')) return 'add';
  if (line.startsWith('-')) return 'del';
  return 'meta';
}

const KIND_CLASS: Record<LineKind, string> = {
  add: 'bg-sentinel-green/10 text-sentinel-green-glow',
  del: 'bg-sentinel-red/10 text-sentinel-red-glow',
  hunk: 'bg-sentinel-blue/10 text-sentinel-blue-glow',
  meta: 'text-sentinel-text-tertiary',
};

export default function DiffViewer({ diff }: DiffViewerProps) {
  const [copied, setCopied] = useState(false);
  const lines = diff.split('\n');

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(diff);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      /* clipboard unavailable */
    }
  }

  return (
    <div className="glass-soft rounded-glass relative overflow-hidden">
      <button
        type="button"
        onClick={handleCopy}
        className="btn absolute top-2 right-2 z-10 px-2.5 py-1 text-[11px]"
        aria-label="Copy diff"
      >
        {copied ? (
          <>
            <Check className="h-3 w-3" /> Copied
          </>
        ) : (
          <>
            <Copy className="h-3 w-3" /> Copy
          </>
        )}
      </button>
      <pre className="bg-black/40 rounded-glass p-4 pr-20 m-0 overflow-x-auto font-mono text-[12px] leading-[1.55] whitespace-pre-wrap break-words">
        {lines.map((line, i) => {
          const kind = classify(line);
          return (
            <div
              key={i}
              className={clsx(
                'px-2 -mx-2 rounded-sm',
                KIND_CLASS[kind],
              )}
            >
              {line.length === 0 ? ' ' : line}
            </div>
          );
        })}
      </pre>
    </div>
  );
}
