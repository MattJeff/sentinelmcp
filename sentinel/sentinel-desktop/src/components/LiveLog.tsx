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
      <header className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-sentinel-blue-glow" />
          <h2 className="text-[15px] font-semibold tracking-tight">Activity log</h2>
        </div>
        <span className="section-heading">{entries.length} lines</span>
      </header>

      <div
        ref={scrollRef}
        className="bg-black/30 rounded-glass p-4 max-h-96 md:max-h-[28rem] overflow-y-auto font-mono text-[12px] leading-relaxed border border-white/5 w-full"
      >
        {entries.length === 0 ? (
          <div className="flex h-72 items-center justify-center text-sentinel-text-tertiary text-[12px] font-sans">
            No activity yet. Start a scan.
          </div>
        ) : (
          <ul className="space-y-1">
            {entries.map((entry, i) => (
              <li key={i} className="flex flex-col sm:flex-row gap-1 sm:gap-3 animate-fade-up">
                <span className="text-sentinel-text-tertiary shrink-0 select-none">
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
