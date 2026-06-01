// Global Cmd+K / Ctrl+K keyboard binding for the command palette.
// Owned by Agent UI-11. Exposes a controllable `open`/`setOpen` pair so the
// consuming layout can also open the palette from a button.

import { useCallback, useEffect, useState } from 'react';

export interface UseCommandPaletteReturn {
  open: boolean;
  setOpen: (open: boolean) => void;
}

/**
 * Mount once at the top of the tree. Binds Cmd+K (Mac) / Ctrl+K (other) to
 * toggle the palette. Returns a controllable open state which the caller
 * passes to <CommandPalette open={open} onOpenChange={setOpen} />.
 */
export function useCommandPalette(): UseCommandPaletteReturn {
  const [open, setOpen] = useState(false);

  const handleSetOpen = useCallback((next: boolean) => {
    setOpen(next);
  }, []);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      // K + (Cmd on Mac, Ctrl elsewhere). Case-insensitive.
      const key = event.key.toLowerCase();
      if (key !== 'k') return;

      const isMac =
        typeof navigator !== 'undefined' &&
        /Mac|iPhone|iPad|iPod/.test(navigator.platform);
      const modifier = isMac ? event.metaKey : event.ctrlKey;
      if (!modifier) return;

      event.preventDefault();
      setOpen((prev) => !prev);
    }

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  return { open, setOpen: handleSetOpen };
}
