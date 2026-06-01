/**
 * Sentinel MCP logo.
 *
 * An inline SVG mirroring the macOS app icon: a rounded shield filled with
 * the Sentinel gradient (blue -> indigo -> purple), an inner highlight for a
 * frosted-glass feel, and a central MCP "lens" (concentric rings + dot).
 *
 * Scalable via the `size` prop (defaults to 32). Pass `title` to set the
 * accessible label; omit it for a purely decorative mark (it becomes
 * aria-hidden in that case).
 *
 * Usage:
 *   import { Logo } from "@/components/Logo";
 *   <Logo size={28} title="Sentinel MCP" />
 *
 * NOTE: This component is intentionally NOT wired into DashboardLayout.tsx —
 * the sidebar wiring is left for a later UI pass to avoid touching files
 * outside this agent's scope.
 */

import * as React from "react";

export interface LogoProps extends React.SVGProps<SVGSVGElement> {
  /** Pixel size of the rendered square logo. Defaults to 32. */
  size?: number;
  /** Optional accessible label. If omitted the SVG is marked decorative. */
  title?: string;
}

let uid = 0;
const nextId = () => `sentinel-logo-${++uid}`;

export const Logo: React.FC<LogoProps> = ({
  size = 32,
  title,
  ...rest
}) => {
  // Stable per-instance IDs so multiple Logos on the same page don't collide.
  const idRef = React.useRef<string>(nextId());
  const gradId = `${idRef.current}-grad`;
  const highlightId = `${idRef.current}-hl`;
  const clipId = `${idRef.current}-clip`;

  const decorative = !title;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 1024 1024"
      xmlns="http://www.w3.org/2000/svg"
      role={decorative ? "presentation" : "img"}
      aria-hidden={decorative ? true : undefined}
      aria-label={title}
      {...rest}
    >
      {title ? <title>{title}</title> : null}

      <defs>
        {/* Sentinel gradient: blue -> indigo -> purple */}
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#3B82F6" />
          <stop offset="50%" stopColor="#6366F1" />
          <stop offset="100%" stopColor="#A855F7" />
        </linearGradient>

        {/* Frosted-glass top highlight */}
        <radialGradient
          id={highlightId}
          cx="0.35"
          cy="0.2"
          r="0.6"
          fx="0.3"
          fy="0.15"
        >
          <stop offset="0%" stopColor="#FFFFFF" stopOpacity="0.55" />
          <stop offset="60%" stopColor="#FFFFFF" stopOpacity="0.05" />
          <stop offset="100%" stopColor="#FFFFFF" stopOpacity="0" />
        </radialGradient>

        {/* Shield silhouette used both as fill region and clip */}
        <clipPath id={clipId}>
          <path d="M512 40
                   C 632 60, 760 100, 880 180
                   C 920 260, 920 420, 880 560
                   C 830 720, 720 840, 600 940
                   C 560 970, 530 985, 512 992
                   C 494 985, 464 970, 424 940
                   C 304 840, 194 720, 144 560
                   C 104 420, 104 260, 144 180
                   C 264 100, 392 60, 512 40 Z" />
        </clipPath>
      </defs>

      {/* Soft outer shadow */}
      <g opacity="0.35" filter="url(#none)">
        <path
          d="M512 56
             C 628 76, 752 114, 868 192
             C 906 270, 906 426, 868 562
             C 820 718, 714 836, 596 934
             C 558 962, 530 977, 512 984
             C 494 977, 466 962, 428 934
             C 310 836, 204 718, 156 562
             C 118 426, 118 270, 156 192
             C 272 114, 396 76, 512 56 Z"
          fill="#0B0A1F"
          transform="translate(0,14)"
        />
      </g>

      {/* Shield body (clipped to shield silhouette) */}
      <g clipPath={`url(#${clipId})`}>
        <rect x="0" y="0" width="1024" height="1024" fill={`url(#${gradId})`} />
        {/* frosted highlight */}
        <rect x="0" y="0" width="1024" height="1024" fill={`url(#${highlightId})`} />
        {/* inner edge darkening */}
        <path
          d="M512 40
             C 632 60, 760 100, 880 180
             C 920 260, 920 420, 880 560
             C 830 720, 720 840, 600 940
             C 560 970, 530 985, 512 992
             C 494 985, 464 970, 424 940
             C 304 840, 194 720, 144 560
             C 104 420, 104 260, 144 180
             C 264 100, 392 60, 512 40 Z"
          fill="none"
          stroke="#0B0A1F"
          strokeWidth="14"
          opacity="0.35"
        />
      </g>

      {/* MCP lens: concentric rings + pupil */}
      <g>
        <circle
          cx="512"
          cy="532"
          r="220"
          fill="none"
          stroke="#FFFFFF"
          strokeOpacity="0.92"
          strokeWidth="18"
        />
        <circle
          cx="512"
          cy="532"
          r="140"
          fill="none"
          stroke="#FFFFFF"
          strokeOpacity="0.78"
          strokeWidth="14"
        />
        <circle cx="512" cy="532" r="56" fill="#FFFFFF" />
        {/* specular highlight */}
        <circle cx="492" cy="512" r="18" fill="#FFFFFF" />
      </g>
    </svg>
  );
};

export default Logo;
