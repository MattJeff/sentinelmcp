// Sidebar state hook — manages collapsed/expanded and mobile drawer state.
// `collapsed` is persisted to localStorage under `sentinel.sidebar.collapsed`.
//
// The DashboardLayout uses Tailwind responsive classes to *force* the icon-rail
// look below `lg` and switch to a drawer below `md`. This hook stores the
// user's preference for the ≥lg state, plus the transient mobile-open flag.

import { useCallback, useEffect, useState } from 'react';

const STORAGE_KEY = 'sentinel.sidebar.collapsed';

function readInitialCollapsed(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (raw === null) return false;
    return raw === 'true' || raw === '1';
  } catch {
    return false;
  }
}

export interface UseSidebarResult {
  collapsed: boolean;
  setCollapsed: (next: boolean | ((prev: boolean) => boolean)) => void;
  mobileOpen: boolean;
  setMobileOpen: (next: boolean | ((prev: boolean) => boolean)) => void;
}

export function useSidebar(): UseSidebarResult {
  const [collapsed, setCollapsedState] = useState<boolean>(() => readInitialCollapsed());
  const [mobileOpen, setMobileOpenState] = useState<boolean>(false);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    try {
      window.localStorage.setItem(STORAGE_KEY, collapsed ? 'true' : 'false');
    } catch {
      /* ignore quota / privacy-mode errors */
    }
  }, [collapsed]);

  const setCollapsed = useCallback(
    (next: boolean | ((prev: boolean) => boolean)) => {
      setCollapsedState((prev) => (typeof next === 'function' ? next(prev) : next));
    },
    [],
  );

  const setMobileOpen = useCallback(
    (next: boolean | ((prev: boolean) => boolean)) => {
      setMobileOpenState((prev) => (typeof next === 'function' ? next(prev) : next));
    },
    [],
  );

  return { collapsed, setCollapsed, mobileOpen, setMobileOpen };
}

export default useSidebar;
