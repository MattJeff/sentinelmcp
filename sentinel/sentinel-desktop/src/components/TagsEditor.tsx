// TagsEditor — lightweight, dependency-free chip editor for the operator-
// curated tag set attached to a server row.
//
// Behaviour:
//   • Type a value, press Enter or "," to commit it as a chip.
//   • Each chip carries an "x" button to remove it.
//   • Autocomplete is fed by an arbitrary suggestion list (typically the
//     output of `api.serverListTags()`) and filtered on the in-flight input.
//   • Normalisation: trim → lowercase → max 32 chars, deduplicated, capped
//     at 32 entries total. Invalid input is silently dropped so paste-bombs
//     don't blow up the persisted row.
//
// The component is fully controlled: parent owns the tag list and decides
// when to persist it (typically via a "Save tags" button placed alongside).

import { useMemo, useRef, useState } from 'react';
import { X } from 'lucide-react';

export const TAG_MAX_LENGTH = 32;
export const TAGS_MAX_COUNT = 32;

/**
 * Normalise a raw input value to the canonical chip form. Returns `null`
 * when the value is empty after normalisation so callers can swallow it.
 */
export function normaliseTag(raw: string): string | null {
  const cleaned = raw.trim().toLowerCase().slice(0, TAG_MAX_LENGTH);
  return cleaned.length === 0 ? null : cleaned;
}

export interface TagsEditorProps {
  value: string[];
  onChange: (next: string[]) => void;
  /** Optional master list of known tags surfaced in the autocomplete menu. */
  suggestions?: string[];
  placeholder?: string;
  /** Disable input + chip removal while a parent save is in flight. */
  disabled?: boolean;
}

export default function TagsEditor({
  value,
  onChange,
  suggestions = [],
  placeholder = 'Add a tag and press Enter…',
  disabled = false,
}: TagsEditorProps) {
  const [input, setInput] = useState('');
  const [focused, setFocused] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const addTag = (raw: string) => {
    const tag = normaliseTag(raw);
    if (!tag) return;
    if (value.includes(tag)) return;
    if (value.length >= TAGS_MAX_COUNT) return;
    onChange([...value, tag]);
  };

  const addMany = (raw: string) => {
    // Comma- or newline-separated bulk paste: split, normalise, dedupe.
    const parts = raw
      .split(/[\n,]+/)
      .map((p) => normaliseTag(p))
      .filter((p): p is string => Boolean(p));
    if (parts.length === 0) return;
    const seen = new Set(value);
    const next = [...value];
    for (const p of parts) {
      if (next.length >= TAGS_MAX_COUNT) break;
      if (seen.has(p)) continue;
      seen.add(p);
      next.push(p);
    }
    if (next.length !== value.length) onChange(next);
  };

  const removeTag = (tag: string) => {
    onChange(value.filter((t) => t !== tag));
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (disabled) return;
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      const raw = input;
      setInput('');
      addTag(raw);
    } else if (e.key === 'Backspace' && input.length === 0 && value.length > 0) {
      e.preventDefault();
      removeTag(value[value.length - 1]);
    }
  };

  const filteredSuggestions = useMemo(() => {
    const q = input.trim().toLowerCase();
    const already = new Set(value);
    const pool = suggestions.filter((s) => !already.has(s));
    if (q.length === 0) return pool.slice(0, 8);
    return pool.filter((s) => s.includes(q)).slice(0, 8);
  }, [input, suggestions, value]);

  const showMenu =
    focused && !disabled && filteredSuggestions.length > 0 && value.length < TAGS_MAX_COUNT;
  const atCap = value.length >= TAGS_MAX_COUNT;

  return (
    <div className="flex flex-col gap-2">
      <div
        className="flex flex-wrap items-center gap-2 rounded-lg border border-sentinel-border bg-sentinel-inset px-2 py-2 transition-colors duration-150 focus-within:border-sentinel-accent focus-within:shadow-focus"
        onClick={() => inputRef.current?.focus()}
      >
        {value.map((tag) => (
          <span
            key={tag}
            className="inline-flex items-center gap-1 rounded-pill px-2 py-0.5 text-caption font-medium bg-sentinel-accent-dim text-sentinel-accent border border-sentinel-accent/20"
            title={tag}
          >
            {tag}
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                removeTag(tag);
              }}
              disabled={disabled}
              className="text-sentinel-accent/80 transition-colors duration-150 hover:text-sentinel-text-primary disabled:opacity-40 focus-visible:outline-none focus-visible:shadow-focus"
              aria-label={`Remove tag ${tag}`}
              title={`Remove ${tag}`}
            >
              <X size={11} />
            </button>
          </span>
        ))}
        <div className="relative flex-1 min-w-[120px]">
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={(e) => {
              const v = e.target.value;
              if (v.includes(',') || v.includes('\n')) {
                // Bulk paste: tokenise around the delimiters.
                addMany(v);
                setInput('');
              } else {
                setInput(v.slice(0, TAG_MAX_LENGTH));
              }
            }}
            onKeyDown={handleKeyDown}
            onFocus={() => setFocused(true)}
            onBlur={() => {
              // Defer so a click on a suggestion can register before the
              // menu unmounts.
              window.setTimeout(() => setFocused(false), 120);
            }}
            placeholder={atCap ? 'Maximum tags reached' : placeholder}
            disabled={disabled || atCap}
            className="w-full bg-transparent text-caption text-sentinel-text-primary placeholder:text-sentinel-text-faint outline-none py-1 px-1"
            aria-label="Add tag"
          />
          {showMenu && (
            <ul
              role="listbox"
              className="absolute left-0 top-full mt-2 z-10 w-full max-h-48 overflow-y-auto rounded-lg border border-sentinel-border bg-sentinel-raised shadow-raised py-1"
            >
              {filteredSuggestions.map((s) => (
                <li key={s}>
                  <button
                    type="button"
                    onMouseDown={(e) => {
                      // Use mouseDown so it fires before the input's blur.
                      e.preventDefault();
                      addTag(s);
                      setInput('');
                      inputRef.current?.focus();
                    }}
                    className="w-full text-left px-3 py-1 text-caption text-sentinel-text-secondary transition-colors duration-150 hover:bg-white/6 hover:text-sentinel-text-primary focus-visible:outline-none focus-visible:shadow-focus"
                  >
                    {s}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
      <div className="text-caption text-sentinel-text-tertiary tabular-nums">
        {value.length}/{TAGS_MAX_COUNT} tags · Enter or comma to add · max{' '}
        {TAG_MAX_LENGTH} chars each
      </div>
    </div>
  );
}
