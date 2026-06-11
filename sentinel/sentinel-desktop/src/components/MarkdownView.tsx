// MarkdownView — tiny pure-TS markdown renderer.
// No external dependencies. Glass-friendly typography aligned with design.md.
// Implemented by Agent UI-7.
//
// Supported syntax:
//   # H1 / ## H2 / ### H3
//   Paragraphs (blank-line separated)
//   **bold**, *italic*, `inline code`
//   Tables with `| --- |` header separator
//   Unordered lists `- ` and ordered lists `1. `
//   Fenced code blocks ```lang ... ```
//   Blockquotes `> `
// HTML is escaped to prevent injection.

import { useMemo, type JSX } from 'react';

interface MarkdownViewProps {
  source: string;
  className?: string;
}

// ─── HTML escaping ────────────────────────────────────────────────────────
function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ─── Inline formatting ────────────────────────────────────────────────────
// Order matters: extract code spans first to avoid mangling them, then bold,
// then italic. We work on already-escaped text so injection is impossible.
function renderInline(rawText: string): string {
  let text = escapeHtml(rawText);

  // Inline code spans `…`
  text = text.replace(/`([^`]+)`/g, (_m, code) => {
    return `<code class="rounded bg-white/8 px-1.5 py-0.5 text-caption font-mono text-sentinel-text-primary">${code}</code>`;
  });

  // Bold **…**
  text = text.replace(/\*\*([^*]+)\*\*/g, '<strong class="font-semibold text-sentinel-text-primary">$1</strong>');

  // Italic *…* (avoid matching list markers — those were stripped earlier)
  text = text.replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em class="italic">$2</em>');

  return text;
}

// ─── Block parsing ────────────────────────────────────────────────────────
type Block =
  | { kind: 'h1' | 'h2' | 'h3'; text: string }
  | { kind: 'p'; text: string }
  | { kind: 'ul'; items: string[] }
  | { kind: 'ol'; items: string[] }
  | { kind: 'quote'; text: string }
  | { kind: 'code'; lang: string | null; content: string }
  | { kind: 'table'; head: string[]; rows: string[][] };

function parseBlocks(source: string): Block[] {
  const lines = source.replace(/\r\n/g, '\n').split('\n');
  const blocks: Block[] = [];

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];

    // Fenced code blocks
    const fence = /^```(\w+)?\s*$/.exec(line);
    if (fence) {
      const lang = fence[1] ?? null;
      const body: string[] = [];
      i += 1;
      while (i < lines.length && !/^```\s*$/.test(lines[i])) {
        body.push(lines[i]);
        i += 1;
      }
      i += 1; // skip closing fence
      blocks.push({ kind: 'code', lang, content: body.join('\n') });
      continue;
    }

    // Blank lines = block separators
    if (/^\s*$/.test(line)) {
      i += 1;
      continue;
    }

    // Headings
    const h = /^(#{1,3})\s+(.*)$/.exec(line);
    if (h) {
      const level = h[1].length as 1 | 2 | 3;
      blocks.push({
        kind: (level === 1 ? 'h1' : level === 2 ? 'h2' : 'h3'),
        text: h[2].trim(),
      });
      i += 1;
      continue;
    }

    // Blockquote
    if (/^>\s?/.test(line)) {
      const buf: string[] = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) {
        buf.push(lines[i].replace(/^>\s?/, ''));
        i += 1;
      }
      blocks.push({ kind: 'quote', text: buf.join(' ') });
      continue;
    }

    // Tables (header row + separator row of dashes)
    if (/\|/.test(line) && i + 1 < lines.length && /^\s*\|?[\s:|-]+\|[\s:|-]+/.test(lines[i + 1])) {
      const head = splitRow(line);
      i += 2; // skip header + separator
      const rows: string[][] = [];
      while (i < lines.length && /\|/.test(lines[i]) && !/^\s*$/.test(lines[i])) {
        rows.push(splitRow(lines[i]));
        i += 1;
      }
      blocks.push({ kind: 'table', head, rows });
      continue;
    }

    // Unordered list
    if (/^\s*-\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*-\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*-\s+/, ''));
        i += 1;
      }
      blocks.push({ kind: 'ul', items });
      continue;
    }

    // Ordered list
    if (/^\s*\d+\.\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*\d+\.\s+/, ''));
        i += 1;
      }
      blocks.push({ kind: 'ol', items });
      continue;
    }

    // Paragraph (collect contiguous non-empty, non-special lines)
    const para: string[] = [line];
    i += 1;
    while (i < lines.length && !/^\s*$/.test(lines[i]) && !isBlockStart(lines[i], lines[i + 1])) {
      para.push(lines[i]);
      i += 1;
    }
    blocks.push({ kind: 'p', text: para.join(' ') });
  }

  return blocks;
}

function splitRow(line: string): string[] {
  // Trim leading/trailing pipes then split.
  return line
    .replace(/^\s*\|/, '')
    .replace(/\|\s*$/, '')
    .split('|')
    .map((c) => c.trim());
}

function isBlockStart(line: string, next: string | undefined): boolean {
  if (/^#{1,3}\s+/.test(line)) return true;
  if (/^\s*-\s+/.test(line)) return true;
  if (/^\s*\d+\.\s+/.test(line)) return true;
  if (/^>\s?/.test(line)) return true;
  if (/^```/.test(line)) return true;
  if (/\|/.test(line) && next && /^\s*\|?[\s:|-]+\|[\s:|-]+/.test(next)) return true;
  return false;
}

// ─── Rendering ────────────────────────────────────────────────────────────
function renderBlock(block: Block, key: number): JSX.Element {
  switch (block.kind) {
    case 'h1':
      return (
        <h1
          key={key}
          className="text-metric font-semibold tracking-tight text-sentinel-text-primary mt-8 mb-3 first:mt-0"
          dangerouslySetInnerHTML={{ __html: renderInline(block.text) }}
        />
      );
    case 'h2':
      return (
        <h2
          key={key}
          className="text-title text-sentinel-text-primary mt-8 mb-2 first:mt-0"
          dangerouslySetInnerHTML={{ __html: renderInline(block.text) }}
        />
      );
    case 'h3':
      return (
        <h3
          key={key}
          className="text-overline uppercase text-sentinel-text-secondary mt-6 mb-2 first:mt-0"
          dangerouslySetInnerHTML={{ __html: renderInline(block.text) }}
        />
      );
    case 'p':
      return (
        <p
          key={key}
          className="text-body leading-relaxed text-sentinel-text-secondary my-3 max-w-prose"
          dangerouslySetInnerHTML={{ __html: renderInline(block.text) }}
        />
      );
    case 'ul':
      return (
        <ul key={key} className="my-3 space-y-2 pl-6 list-disc marker:text-sentinel-text-tertiary">
          {block.items.map((item, idx) => (
            <li
              key={idx}
              className="text-body leading-relaxed text-sentinel-text-secondary"
              dangerouslySetInnerHTML={{ __html: renderInline(item) }}
            />
          ))}
        </ul>
      );
    case 'ol':
      return (
        <ol key={key} className="my-3 space-y-2 pl-6 list-decimal marker:text-sentinel-text-tertiary tabular-nums">
          {block.items.map((item, idx) => (
            <li
              key={idx}
              className="text-body leading-relaxed text-sentinel-text-secondary"
              dangerouslySetInnerHTML={{ __html: renderInline(item) }}
            />
          ))}
        </ol>
      );
    case 'quote':
      return (
        <blockquote
          key={key}
          className="my-4 pl-4 border-l-2 border-sentinel-accent text-body italic text-sentinel-text-secondary"
          dangerouslySetInnerHTML={{ __html: renderInline(block.text) }}
        />
      );
    case 'code':
      return (
        <pre
          key={key}
          className="bg-sentinel-inset border border-sentinel-border-soft rounded-lg my-4 p-4 overflow-x-auto text-caption font-mono leading-relaxed text-sentinel-text-primary"
        >
          {block.lang && (
            <div className="section-heading mb-2">{block.lang}</div>
          )}
          <code dangerouslySetInnerHTML={{ __html: escapeHtml(block.content) }} />
        </pre>
      );
    case 'table':
      return (
        <div key={key} className="my-4 overflow-x-auto rounded-lg border border-sentinel-border-soft bg-sentinel-inset">
          <table className="w-full text-caption">
            <thead>
              <tr className="border-b border-sentinel-border">
                {block.head.map((cell, idx) => (
                  <th
                    key={idx}
                    className="px-4 py-2 text-left text-overline uppercase text-sentinel-text-tertiary"
                    dangerouslySetInnerHTML={{ __html: renderInline(cell) }}
                  />
                ))}
              </tr>
            </thead>
            <tbody>
              {block.rows.map((row, rIdx) => (
                <tr
                  key={rIdx}
                  className="border-b border-sentinel-border-soft last:border-0 transition-colors duration-150 hover:bg-white/3"
                >
                  {row.map((cell, cIdx) => (
                    <td
                      key={cIdx}
                      className="px-4 py-2 text-sentinel-text-secondary align-top"
                      dangerouslySetInnerHTML={{ __html: renderInline(cell) }}
                    />
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
  }
}

export default function MarkdownView({ source, className }: MarkdownViewProps) {
  const blocks = useMemo(() => parseBlocks(source ?? ''), [source]);
  return (
    <div className={['markdown-view', className].filter(Boolean).join(' ')}>
      {blocks.map((block, idx) => renderBlock(block, idx))}
    </div>
  );
}
