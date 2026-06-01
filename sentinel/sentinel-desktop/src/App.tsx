// Root shell — wires onboarding, dashboard, toaster, and command palette.
// Owned by Agent UI-18.
//
// The active page is lifted up here so the command palette (mounted at the
// same level) can switch pages via its `onNavigate` callback. The drawer
// for an arbitrary server is reachable from the palette by navigating to
// Inventory first; opening the drawer directly across pages is a future
// iteration (the contract here is: palette → Inventory page).

import { useCallback, useState } from 'react';

import DashboardLayout, { type NavId } from './components/DashboardLayout';
import Welcome from './components/Welcome';
import Toaster from './components/Toaster';
import CommandPalette, {
  type CommandPalettePageId,
} from './components/CommandPalette';
import { useOnboarding } from './hooks/useOnboarding';
import { useCommandPalette } from './hooks/useCommandPalette';

export default function App() {
  const { done } = useOnboarding();
  const { open: paletteOpen, setOpen: setPaletteOpen } = useCommandPalette();
  const [active, setActive] = useState<NavId>('overview');

  const handleNavigate = useCallback(
    (pageId: CommandPalettePageId) => {
      setActive(pageId as NavId);
    },
    [],
  );

  const handleSelectServer = useCallback(
    (id: string) => {
      // Surface the server in the Inventory page; persist a transient
      // pending-id in sessionStorage so InventoryPage can pop its drawer
      // on mount/route-change without needing a global store.
      try {
        sessionStorage.setItem('sentinel.pendingServerId', id);
      } catch {
        // sessionStorage can throw in private mode; selection still navigates.
      }
      setActive('inventory');
    },
    [],
  );

  if (!done) {
    return <Welcome />;
  }

  return (
    <>
      {/* Global drag strip so the whole top edge of the window can move the app. */}
      <div className="window-drag-strip" aria-hidden />
      <DashboardLayout
        active={active}
        onActiveChange={setActive}
        onOpenCommandPalette={() => setPaletteOpen(true)}
      />
      <Toaster />
      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        onNavigate={handleNavigate}
        onSelectServer={handleSelectServer}
      />
    </>
  );
}
