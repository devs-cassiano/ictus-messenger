import { sanitizePlainMessageText } from '../utils/sanitizeMessage';

interface SafeMessageTextProps {
  text: string;
  as?: 'p' | 'span';
  className?: string;
}

/**
 * Renders decrypted chat text as a plain React string (HTML-escaped by React).
 * DOMPurify strips tags first as defense-in-depth — no dangerouslySetInnerHTML.
 */
export function SafeMessageText({
  text,
  as = 'p',
  className,
}: SafeMessageTextProps) {
  const safe = sanitizePlainMessageText(text);
  if (as === 'span') {
    return <span className={className}>{safe}</span>;
  }
  return <p className={className}>{safe}</p>;
}
