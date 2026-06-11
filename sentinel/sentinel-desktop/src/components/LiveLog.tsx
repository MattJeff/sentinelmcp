// Live, auto-scrolling mono log used by the Scan page.
import { useEffect, useRef } from 'react';
import { Terminal } from 'lucide-react';

export interface LogEntry {
  ts: number;
  message: string;
}

interface LiveLogProps {
  entries: LogEntry[];
}

function formatTs(ts: number): string {
  const d = new Date(ts);
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  const ms = String(d.getMilliseconds()).padStart(3, '0');
  return `${hh}:${mm}:${ss}.${ms}`;
}

export default function LiveLog({ entries }: LiveLogProps) {
  const scrollRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [entries]);

  return (
    <section className="card animate-fade-up w-full">
      <header className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-sentinel-accent" aria-hidden="true" />
          <h2 className="text-title text-sentinel-text-primary">Activity log</h2>
        </div>
        <span className="section-heading tabular-nums">{entries.length} lines</span>
      </header>

      <div
        ref={scrollRef}
        role="log"
        aria-label="Activity log"
        className="w-full max-h-96 md:max-h-[28rem] overflow-y-auto rounded-glass border border-sentinel-border-soft bg-sentinel-deep p-4 font-mono text-caption leading-relaxed"
      >
        {entries.length === 0 ? (
          <div className="flex h-72 items-center justify-center font-sans text-caption text-sentinel-text-tertiary">
            No activity yet. Start a scan.
          </div>
        ) : (
          <ul className="space-y-1">
            {entries.map((entry, i) => (
              <li key={i} className="flex flex-col sm:flex-row gap-1 sm:gap-3 animate-fade-up">
                <span className="shrink-0 select-none text-sentinel-text-tertiary tabular-nums">
                  {formatTs(entry.ts)}
                </span>
                <span className="text-sentinel-text-primary break-words whitespace-pre-wrap min-w-0">
                  {entry.message}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
