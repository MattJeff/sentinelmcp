// Apple-style settings row used by the Settings page.
// Implemented by Agent UI-8.

import type { ReactNode } from 'react';
import clsx from 'clsx';

export interface SettingRowProps {
  label: ReactNode;
  description?: ReactNode;
  /** Optional id to associate with the control via aria-labelledby. */
  htmlForId?: string;
  /** Right-aligned control(s). */
  children: ReactNode;
  /** Drop the bottom hairline (use on the last row of a card). */
  last?: boolean;
  /** Stack control under the label on the same row (useful for full-width inputs). */
  align?: 'center' | 'top';
  className?: string;
}

export default function SettingRow({
  label,
  description,
  htmlForId,
  children,
  last,
  align = 'center',
  className,
}: SettingRowProps) {
  return (
    <div
      className={clsx(
        'flex flex-col sm:flex-row gap-2 sm:gap-6 py-4',
        align === 'center' ? 'sm:items-center' : 'sm:items-start',
        !last && 'border-b border-sentinel-border-soft',
        className,
      )}
    >
      <div className="flex-1 min-w-0">
        <label
          htmlFor={htmlForId}
          className="block text-body font-medium text-sentinel-text-primary"
        >
          {label}
        </label>
        {description && (
          <div className="mt-1 max-w-prose text-caption text-sentinel-text-tertiary">
            {description}
          </div>
        )}
      </div>
      <div className="sm:shrink-0 flex flex-wrap items-center gap-2 sm:justify-end">
        {children}
      </div>
    </div>
  );
}
