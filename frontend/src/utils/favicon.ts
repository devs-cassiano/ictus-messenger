/**
 * Dynamic favicon notification dot for background-tab unread messages.
 * Draws a badge onto a canvas copy of the original icon; restores on clear.
 */

const DEFAULT_ICON_HREF = '/favicon.svg';
const BADGE_COLOR = '#ef4444';
const BADGE_STROKE = '#ffffff';
const CANVAS_SIZE = 32;

let originalHref: string | null = null;
let originalType: string | null = null;
let badgeGeneration = 0;
let badgeActive = false;

function getIconLink(): HTMLLinkElement | null {
  return document.querySelector<HTMLLinkElement>("link[rel*='icon']");
}

function ensureIconLink(): HTMLLinkElement {
  const existing = getIconLink();
  if (existing) {
    return existing;
  }
  const created = document.createElement('link');
  created.rel = 'icon';
  created.href = DEFAULT_ICON_HREF;
  document.head.appendChild(created);
  return created;
}

function captureOriginalIcon(): void {
  if (originalHref) {
    return;
  }
  const link = ensureIconLink();
  originalHref = link.getAttribute('href') || DEFAULT_ICON_HREF;
  originalType = link.getAttribute('type');
}

function drawNotificationDot(ctx: CanvasRenderingContext2D): void {
  ctx.beginPath();
  ctx.arc(24, 8, 6, 0, Math.PI * 2);
  ctx.fillStyle = BADGE_COLOR;
  ctx.fill();
  ctx.lineWidth = 1.5;
  ctx.strokeStyle = BADGE_STROKE;
  ctx.stroke();
}

function applyCanvasBadge(
  link: HTMLLinkElement,
  drawBase: (ctx: CanvasRenderingContext2D, size: number) => void,
): void {
  const canvas = document.createElement('canvas');
  canvas.width = CANVAS_SIZE;
  canvas.height = CANVAS_SIZE;
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    return;
  }
  ctx.clearRect(0, 0, CANVAS_SIZE, CANVAS_SIZE);
  drawBase(ctx, CANVAS_SIZE);
  drawNotificationDot(ctx);
  link.type = 'image/png';
  link.href = canvas.toDataURL('image/png');
}

/** Fallback when the source favicon fails to load or taints the canvas. */
function drawFallbackIcon(ctx: CanvasRenderingContext2D, size: number): void {
  const radius = size * 0.22;
  ctx.fillStyle = '#0d1b1e';
  ctx.beginPath();
  ctx.moveTo(radius, 0);
  ctx.arcTo(size, 0, size, size, radius);
  ctx.arcTo(size, size, 0, size, radius);
  ctx.arcTo(0, size, 0, 0, radius);
  ctx.arcTo(0, 0, size, 0, radius);
  ctx.closePath();
  ctx.fill();

  ctx.strokeStyle = '#2dd4bf';
  ctx.lineWidth = size * 0.07;
  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';
  ctx.beginPath();
  ctx.moveTo(size * 0.2, size * 0.5);
  ctx.bezierCurveTo(
    size * 0.38,
    size * 0.25,
    size * 0.68,
    size * 0.3,
    size * 0.8,
    size * 0.5,
  );
  ctx.bezierCurveTo(
    size * 0.68,
    size * 0.7,
    size * 0.38,
    size * 0.75,
    size * 0.2,
    size * 0.5,
  );
  ctx.stroke();
}

/**
 * Toggle the unread notification dot on the page favicon.
 * Safe to call repeatedly; restores the captured original href when cleared.
 */
export function setFaviconBadge(hasUnread: boolean): void {
  if (typeof document === 'undefined') {
    return;
  }

  captureOriginalIcon();
  const link = ensureIconLink();
  const href = originalHref ?? DEFAULT_ICON_HREF;

  if (!hasUnread) {
    badgeActive = false;
    badgeGeneration += 1;
    link.href = href;
    if (originalType) {
      link.type = originalType;
    } else {
      link.removeAttribute('type');
    }
    return;
  }

  badgeActive = true;
  const generation = ++badgeGeneration;

  const img = new Image();
  img.decoding = 'async';

  img.onload = () => {
    if (!badgeActive || generation !== badgeGeneration) {
      return;
    }
    try {
      applyCanvasBadge(link, (ctx, size) => {
        ctx.drawImage(img, 0, 0, size, size);
      });
    } catch {
      if (!badgeActive || generation !== badgeGeneration) {
        return;
      }
      applyCanvasBadge(link, drawFallbackIcon);
    }
  };

  img.onerror = () => {
    if (!badgeActive || generation !== badgeGeneration) {
      return;
    }
    try {
      applyCanvasBadge(link, drawFallbackIcon);
    } catch {
      // Last resort: leave original favicon untouched.
    }
  };

  // Cache-bust relative SVG so onload always fires after a restore cycle.
  const separator = href.includes('?') ? '&' : '?';
  img.src =
    href.startsWith('data:') || href.startsWith('blob:')
      ? href
      : `${href}${separator}v=${generation}`;
}

const BASE_DOCUMENT_TITLE = 'Ictus Messenger';

/** Sync the tab title with an unread count, e.g. `(3) Ictus Messenger`. */
export function setDocumentUnreadTitle(count: number): void {
  if (typeof document === 'undefined') {
    return;
  }
  if (count <= 0) {
    document.title = BASE_DOCUMENT_TITLE;
    return;
  }
  const label = count > 99 ? '99+' : String(count);
  document.title = `(${label}) ${BASE_DOCUMENT_TITLE}`;
}

export function clearFaviconNotifications(): void {
  setFaviconBadge(false);
  setDocumentUnreadTitle(0);
}
