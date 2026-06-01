// useDiscoveryAuth — gates the Discovery page on explicit user consent.
// Storage policy:
//   - "Allow once"   → sessionStorage (cleared when the window closes)
//   - "Allow always" → localStorage   (persisted across launches)
// Either grants permission for the current session.

import { useCallback, useEffect } from 'react';
import { create } from 'zustand';

const STORAGE_KEY = 'sentinel.discovery.auth';
const SESSION_VALUE = 'session';
const ALWAYS_VALUE = 'always';

export type DiscoveryAuthMode = 'none' | 'session' | 'always';

interface AuthStore {
  mode: DiscoveryAuthMode;
  setMode: (mode: DiscoveryAuthMode) => void;
}

function readInitial(): DiscoveryAuthMode {
  if (typeof window === 'undefined') return 'none';
  try {
    if (window.localStorage.getItem(STORAGE_KEY) === ALWAYS_VALUE) return 'always';
  } catch {
    /* ignore */
  }
  try {
    if (window.sessionStorage.getItem(STORAGE_KEY) === SESSION_VALUE) return 'session';
  } catch {
    /* ignore */
  }
  return 'none';
}

const useAuthStore = create<AuthStore>((set) => ({
  mode: readInitial(),
  setMode: (mode) => set({ mode }),
}));

export interface UseDiscoveryAuth {
  /** True when the user has granted permission for this session. */
  authorized: boolean;
  mode: DiscoveryAuthMode;
  allowOnce: () => void;
  allowAlways: () => void;
  reset: () => void;
}

export function useDiscoveryAuth(): UseDiscoveryAuth {
  const mode = useAuthStore((s) => s.mode);
  const setMode = useAuthStore((s) => s.setMode);

  // Cross-tab/window sync: if another window grants permission, mirror it here.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const onStorage = (e: StorageEvent) => {
      if (e.key !== STORAGE_KEY) return;
      if (e.newValue === ALWAYS_VALUE) setMode('always');
      else if (e.newValue === null) setMode(readInitial());
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, [setMode]);

  const allowOnce = useCallback(() => {
    try {
      window.sessionStorage.setItem(STORAGE_KEY, SESSION_VALUE);
    } catch {
      /* ignore */
    }
    setMode('session');
  }, [setMode]);

  const allowAlways = useCallback(() => {
    try {
      window.localStorage.setItem(STORAGE_KEY, ALWAYS_VALUE);
    } catch {
      /* ignore */
    }
    setMode('always');
  }, [setMode]);

  const reset = useCallback(() => {
    try {
      window.localStorage.removeItem(STORAGE_KEY);
      window.sessionStorage.removeItem(STORAGE_KEY);
    } catch {
      /* ignore */
    }
    setMode('none');
  }, [setMode]);

  return {
    authorized: mode !== 'none',
    mode,
    allowOnce,
    allowAlways,
    reset,
  };
}

export default useDiscoveryAuth;
