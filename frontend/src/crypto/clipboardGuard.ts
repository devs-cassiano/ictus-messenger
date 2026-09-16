/** Clears the system clipboard after a delay (anti-forensic hygiene). */
const DEFAULT_CLEAR_MS = 30_000;

let clearTimer: ReturnType<typeof setTimeout> | null = null;

/**
 * Schedule wiping the clipboard contents. Resets the timer on each call.
 * Image clipboard entries are best-effort cleared via empty text write.
 */
export function scheduleClipboardClear(delayMs = DEFAULT_CLEAR_MS): void {
  if (clearTimer !== null) {
    clearTimeout(clearTimer);
    clearTimer = null;
  }
  clearTimer = setTimeout(() => {
    clearTimer = null;
    void navigator.clipboard.writeText('').catch(() => {
      // Clipboard permission may be denied — ignore.
    });
  }, delayMs);
}
