/**
 * XSS-safe message body helpers (DOMPurify).
 * Chat content is treated as plain text by default — no HTML parsing in React.
 */

import DOMPurify from 'dompurify';
import { clampMessageText } from './validators';

const ALLOWED_INLINE_TAGS = ['b', 'i', 'em', 'strong', 'code', 'pre', 'br'] as const;

/**
 * Strip all HTML — React then renders the result as a text child (escaped).
 */
export function sanitizePlainMessageText(content: string): string {
  const bounded = clampMessageText(content);
  return DOMPurify.sanitize(bounded, {
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: [],
    KEEP_CONTENT: true,
  });
}

/**
 * Optional rich-text sanitizer when HTML fragments are intentionally allowed.
 * Disarms javascript:/data:/vbscript: URLs; only http(s) links survive.
 */
export function sanitizeRichMessageHtml(content: string): string {
  const bounded = clampMessageText(content);
  const clean = DOMPurify.sanitize(bounded, {
    ALLOWED_TAGS: [...ALLOWED_INLINE_TAGS, 'a'],
    ALLOWED_ATTR: ['href', 'rel', 'target'],
    ALLOW_DATA_ATTR: false,
    ALLOWED_URI_REGEXP: /^(?:https?):/i,
  });

  // Force safe link attributes when any <a> remains.
  if (typeof DOMParser === 'undefined') {
    return clean;
  }
  const doc = new DOMParser().parseFromString(clean, 'text/html');
  doc.querySelectorAll('a').forEach((anchor) => {
    const href = anchor.getAttribute('href') ?? '';
    if (!/^https?:\/\//i.test(href)) {
      anchor.removeAttribute('href');
      return;
    }
    anchor.setAttribute('rel', 'noopener noreferrer');
    anchor.setAttribute('target', '_blank');
  });
  return doc.body.innerHTML;
}
