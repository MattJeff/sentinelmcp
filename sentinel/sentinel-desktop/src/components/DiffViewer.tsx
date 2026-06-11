// DiffViewer — renders a unified/markdown diff with semantic ok/critical/accent tints.
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
  add: 'bg-sentinel-ok-bg text-sentinel-ok',
  del: 'bg-sentinel-critical-bg text-sentinel-critical',
  hunk: 'bg-sentinel-accent-dim text-sentinel-accent',
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
        className="btn btn-sm absolute top-3 right-3 z-10 text-caption"
        aria-label="Copy diff"
        aria-live="polite"
      >
        {copied ? (
          <>
            <Check className="h-3 w-3" aria-hidden /> Copied
          </>
        ) : (
          <>
            <Copy className="h-3 w-3" aria-hidden /> Copy
          </>
        )}
      </button>
      <pre className="bg-sentinel-inset rounded-glass p-4 pr-24 m-0 overflow-x-auto font-mono text-caption leading-5 whitespace-pre-wrap break-words">
        {lines.map((line, i) => {
          const kind = classify(line);
          return (
            <div
              key={i}
              className={clsx(
                'px-2 -mx-2',
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
