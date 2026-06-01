import { useCallback, useEffect, useState } from 'react';

const STORAGE_KEY = 'sentinel.onboarding.dismissed';

function readDismissed(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    return window.localStorage.getItem(STORAGE_KEY) === 'true';
  } catch {
    return false;
  }
}

export interface UseOnboarding {
  done: boolean;
  dismiss: () => void;
}

export function useOnboarding(): UseOnboarding {
  const [done, setDone] = useState<boolean>(() => readDismissed());

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const onStorage = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY) {
        setDone(e.newValue === 'true');
      }
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  const dismiss = useCallback(() => {
    try {
      window.localStorage.setItem(STORAGE_KEY, 'true');
    } catch {
      // ignore — fall through to in-memory dismissal
    }
    // Force a clean document reload instead of an in-place React re-render.
    // The Welcome → Dashboard transition has been observed to leave the
    // WKWebView blank on macOS in production builds; a reload guarantees
    // the dashboard mounts from a fresh document.
    if (typeof window !== 'undefined') {
      window.location.reload();
      return;
    }
    setDone(true);
  }, []);

  return { done, dismiss };
}

export default useOnboarding;
