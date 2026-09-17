import type { ReactNode, SVGProps } from 'react';

/** Inactive / default icon tone (slate). */
export const ICON_MUTED = '#94a3b8';
/** Active / hover icon tone (petroleum teal). */
export const ICON_ACTIVE = '#2dd4bf';

export type IconSize = 'sm' | 'md' | 'nav';

export interface UiIconProps {
  title?: string;
  /** sm=18, md=20 (default), nav=22 */
  size?: IconSize;
  className?: string;
}

const SIZE_PX: Record<IconSize, number> = {
  sm: 18,
  md: 20,
  nav: 22,
};

const STROKE = 1.75;

function IconRoot({
  title,
  size = 'md',
  className,
  children,
}: UiIconProps & { children: ReactNode }) {
  const px = SIZE_PX[size];
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={px}
      height={px}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={STROKE}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className ? `ui-icon ${className}` : 'ui-icon'}
      aria-hidden={title ? undefined : true}
      role={title ? 'img' : undefined}
    >
      {title ? <title>{title}</title> : null}
      {children}
    </svg>
  );
}

type PathProps = SVGProps<SVGPathElement>;

/** Single-tone path — color inherited via currentColor. */
function Stroke(props: PathProps) {
  return <path fill="none" stroke="currentColor" strokeWidth={STROKE} {...props} />;
}

/** + */
export function IconPlus(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M12 5v14M5 12h14" />
    </IconRoot>
  );
}

/** New chat: bubble + plus. */
export function IconMessagePlus(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M21 11.5a8.5 8.5 0 0 1-12.4 7.5L3 21l1.9-4.6A8.5 8.5 0 1 1 21 11.5z" />
      <Stroke d="M12 8v6M9 11h6" />
    </IconRoot>
  );
}

/** Users with + (new group). */
export function IconUsersPlus(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
      <Stroke d="M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z" />
      <Stroke d="M19 8v6M22 11h-6" />
    </IconRoot>
  );
}

export function IconUsers(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
      <Stroke d="M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z" />
      <Stroke d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" />
    </IconRoot>
  );
}

export function IconRefresh(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M21 12a9 9 0 1 1-2.6-6.4" />
      <Stroke d="M21 3v6h-6" />
    </IconRoot>
  );
}

export function IconCopy(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M9 9h11v11H9z" />
      <Stroke d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </IconRoot>
  );
}

export function IconCheck(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M20 6 9 17l-5-5" />
    </IconRoot>
  );
}

export function IconX(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M18 6 6 18M6 6l12 12" />
    </IconRoot>
  );
}

export function IconPaperclip(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" />
    </IconRoot>
  );
}

export function IconSend(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="m22 2-7 20-4-9-9-4z" />
      <Stroke d="M22 2 11 13" />
    </IconRoot>
  );
}

export function IconFlame(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M12 3c2 3 2 5 1 7 3-1 5 1 5 4a6 6 0 0 1-12 0c0-4 3-6 6-11z" />
    </IconRoot>
  );
}

export function IconTrash(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M3 6h18" />
      <Stroke d="M8 6V4h8v2" />
      <Stroke d="M19 6l-1 14H6L5 6" />
      <Stroke d="M10 11v6M14 11v6" />
    </IconRoot>
  );
}

export function IconChevronLeft(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="m15 18-6-6 6-6" />
    </IconRoot>
  );
}

export function IconChevronDown(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="m6 9 6 6 6-6" />
    </IconRoot>
  );
}

/** Collapse sidebar — panel with left chevron. */
export function IconPanelLeftClose(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M4 5h16v14H4z" />
      <Stroke d="M9 5v14" />
      <Stroke d="m15 9-3 3 3 3" />
    </IconRoot>
  );
}

/** Expand sidebar — panel with right chevron. */
export function IconPanelLeftOpen(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M4 5h16v14H4z" />
      <Stroke d="M9 5v14" />
      <Stroke d="m12 9 3 3-3 3" />
    </IconRoot>
  );
}

export function IconClock(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z" />
      <Stroke d="M12 7v5l3 2" />
    </IconRoot>
  );
}

export function IconPencil(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M12 20h9" />
      <Stroke d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z" />
    </IconRoot>
  );
}

export function IconEye(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" />
      <Stroke d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z" />
    </IconRoot>
  );
}

export function IconEyeOff(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M2 12s3.5-7 10-7c2.2 0 4.1.7 5.7 1.7" />
      <Stroke d="M22 12s-3.5 7-10 7c-2.2 0-4.1-.7-5.7-1.7" />
      <Stroke d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
      <Stroke d="M3 3l18 18" />
    </IconRoot>
  );
}

export function IconDownload(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M12 3v12" />
      <Stroke d="m7 10 5 5 5-5" />
      <Stroke d="M5 21h14" />
    </IconRoot>
  );
}

export function IconImage(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M4 5h16v14H4z" />
      <Stroke d="M4 16l4.5-4.5L12 15l3-3 5 5" />
      <Stroke d="M9 10a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3z" />
    </IconRoot>
  );
}

export function IconFile(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M14 2H7a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
      <Stroke d="M14 2v6h6M9 13h6M9 17h6" />
    </IconRoot>
  );
}

export function IconShield(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M12 3 4 6v6c0 5 3.5 8.5 8 9.5 4.5-1 8-4.5 8-9.5V6z" />
      <Stroke d="M9 12l2 2 4-4" />
    </IconRoot>
  );
}

export function IconMoreVertical(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M12 6.5a1 1 0 1 0 0-2 1 1 0 0 0 0 2z" />
      <Stroke d="M12 13a1 1 0 1 0 0-2 1 1 0 0 0 0 2z" />
      <Stroke d="M12 19.5a1 1 0 1 0 0-2 1 1 0 0 0 0 2z" />
    </IconRoot>
  );
}

export function IconInfinity(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M5 12c0-2 1.5-3.5 3.5-3.5S12 10 12 12s1.5 3.5 3.5 3.5S19 14 19 12s-1.5-3.5-3.5-3.5S12 10 12 12s-1.5 3.5-3.5 3.5S5 14 5 12z" />
    </IconRoot>
  );
}

export function IconQrCode(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4z" />
      <Stroke d="M14 14h3v3h-3zM18 18h2v2h-2zM14 18h2v2h-2zM18 14h2v2h-2z" />
    </IconRoot>
  );
}

export function IconCamera(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M4 8h3l2-2h6l2 2h3v11H4z" />
      <Stroke d="M12 17a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z" />
    </IconRoot>
  );
}

export function IconUpload(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M12 16V4" />
      <Stroke d="m7 9 5-5 5 5" />
      <Stroke d="M5 20h14" />
    </IconRoot>
  );
}

export function IconLockExport(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M8 11V8a4 4 0 0 1 8 0v3" />
      <Stroke d="M7 11h10v10H7z" />
      <Stroke d="M12 15v3M12 5V2M9 3.5 12 2l3 1.5" />
    </IconRoot>
  );
}

export function IconLockImport(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M8 11V8a4 4 0 0 1 8 0v3" />
      <Stroke d="M7 11h10v10H7z" />
      <Stroke d="M12 2v3M9 3.5 12 5l3-1.5" />
    </IconRoot>
  );
}

export function IconMoreHorizontal(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M6 12a1 1 0 1 0 0-2 1 1 0 0 0 0 2z" />
      <Stroke d="M13 12a1 1 0 1 0 0-2 1 1 0 0 0 0 2z" />
      <Stroke d="M20 12a1 1 0 1 0 0-2 1 1 0 0 0 0 2z" />
    </IconRoot>
  );
}

/** Secure logout — door / exit. */
export function IconLogOut(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M10 17v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h3a2 2 0 0 1 2 2v1" />
      <Stroke d="M15 12H8" />
      <Stroke d="m12 9 3 3-3 3" />
    </IconRoot>
  );
}

/** Panic — alert triangle. */
export function IconPanic(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M12 3 2 20h20L12 3z" />
      <Stroke d="M12 10v4" />
      <Stroke d="M12 17h.01" />
    </IconRoot>
  );
}

/** Languages / globe. */
export function IconGlobe(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z" />
      <Stroke d="M2 12h20" />
      <Stroke d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </IconRoot>
  );
}

/** Support / donate — heart. */
export function IconHeart(props: UiIconProps) {
  return (
    <IconRoot {...props}>
      <Stroke d="M19 14c1.49-1.46 3-3.21 3-5.5A5.5 5.5 0 0 0 16.5 3c-1.76 0-3 .5-4.5 2-1.5-1.5-2.74-2-4.5-2A5.5 5.5 0 0 0 2 8.5c0 2.3 1.5 4.05 3 5.5l7 7Z" />
    </IconRoot>
  );
}
