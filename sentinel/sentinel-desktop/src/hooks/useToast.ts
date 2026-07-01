// useToast — zustand-backed toast store + hook.
// Surfaces real-time alerts as frosted-glass notifications.
// Implemented by Agent UI-12 for the live alert UX.
// Updated by Agent A1: dedup by (title, description), count badge,
// auto-dismiss (4s, 8s for critical), pause-on-hover, working X button.

import { useMemo } from 'react';
import { create } from 'zustand';
import type { Severity } from '../api/contract';

export interface ToastInput {
  title: string;
  description?: string;
  severity?: Severity;
  diff?: string | null;
}

export interface ToastItem {
  id: string;
  title: string;
  description?: string;
  severity: Severity;
  diff: string | null;
  count: number;
  createdAt: number;
  expiresAt: number;
}

interface ToastStore {
  toasts: ToastItem[];
  push: (input: ToastInput) => string;
  dismiss: (id: string) => void;
  clear: () => void;
  pause: (id: string) => void;
  resume: (id: string) => void;
}

const DEFAULT_TIMEOUT_MS = 4000;
const CRITICAL_TIMEOUT_MS = 8000;
const DEDUP_WINDOW_MS = 5000;

// Track active timers so dismissed/cleared toasts cancel their auto-dismiss.
const timers = new Map<string, ReturnType<typeof setTimeout>>();
// Track remaining time when paused (e.g. on hover) so we can resume.
const remainingOnPause = new Map<string, number>();

function makeId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID();
  }
  return `toast-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function timeoutFor(severity: Severity): number {
  return severity === 'critical' ? CRITICAL_TIMEOUT_MS : DEFAULT_TIMEOUT_MS;
}

function clearTimer(id: string): void {
  const handle = timers.get(id);
  if (handle) {
    clearTimeout(handle);
    timers.delete(id);
  }
}

export const useToastStore = create<ToastStore>((set, get) => ({
  toasts: [],
  push: (input) => {
    const severity: Severity = input.severity ?? 'info';
    const now = Date.now();
    const ttl = timeoutFor(severity);
    const existing = get().toasts.find(
      (t) =>
        t.title === input.title &&
        (t.description ?? '') === (input.description ?? '') &&
        now - t.createdAt <= DEDUP_WINDOW_MS,
    );

    if (existing) {
      // Bump count, refresh expiry, restart timer.
      const newExpiresAt = now + ttl;
      set((state) => ({
        toasts: state.toasts.map((t) =>
          t.id === existing.id
            ? { ...t, count: t.count + 1, expiresAt: newExpiresAt }
            : t,
        ),
      }));
      clearTimer(existing.id);
      remainingOnPause.delete(existing.id);
      const handle = setTimeout(() => {
        get().dismiss(existing.id);
      }, ttl);
      timers.set(existing.id, handle);
      return existing.id;
    }

    const id = makeId();
    const item: ToastItem = {
      id,
      title: input.title,
      description: input.description,
      severity,
      diff: input.diff ?? null,
      count: 1,
      createdAt: now,
      expiresAt: now + ttl,
    };
    set((state) => ({ toasts: [...state.toasts, item] }));
    const handle = setTimeout(() => {
      get().dismiss(id);
    }, ttl);
    timers.set(id, handle);
    return id;
  },
  dismiss: (id) => {
    clearTimer(id);
    remainingOnPause.delete(id);
    set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) }));
  },
  clear: () => {
    for (const handle of timers.values()) clearTimeout(handle);
    timers.clear();
    remainingOnPause.clear();
    set({ toasts: [] });
  },
  pause: (id) => {
    const toast = get().toasts.find((t) => t.id === id);
    if (!toast) return;
    if (remainingOnPause.has(id)) return; // already paused
    clearTimer(id);
    const remaining = Math.max(0, toast.expiresAt - Date.now());
    remainingOnPause.set(id, remaining);
  },
  resume: (id) => {
    const remaining = remainingOnPause.get(id);
    if (remaining === undefined) return;
    remainingOnPause.delete(id);
    const newExpiresAt = Date.now() + remaining;
    set((state) => ({
      toasts: state.toasts.map((t) =>
        t.id === id ? { ...t, expiresAt: newExpiresAt } : t,
      ),
    }));
    const handle = setTimeout(() => {
      get().dismiss(id);
    }, remaining);
    timers.set(id, handle);
  },
}));

export function useToast() {
  // `push` is a zustand action → stable across renders. Memoize the returned
  // object/functions on it so `toast` keeps a STABLE identity: components that
  // list `toast` in a useEffect dependency array (e.g. DetectionSettings) would
  // otherwise re-run their effect every render — an infinite fetch/render loop.
  const push = useToastStore((s) => s.push);
  return useMemo(
    () => ({
      toast: (input: ToastInput) => {
        push(input);
      },
      /**
       * Surface a Discovery-scan summary toast. Called by DiscoveryPage when a
       * fresh scan lands so the user sees an inline acknowledgement (matches
       * the cadence of the Live Scan progress toasts).
       */
      addDiscoveryToast: (clientCount: number, serverCount: number) => {
        push({
          title: `Scan complete · ${clientCount} client${clientCount === 1 ? '' : 's'} · ${serverCount} declared server${serverCount === 1 ? '' : 's'}`,
          severity: 'info',
        });
      },
    }),
    [push],
  );
}
