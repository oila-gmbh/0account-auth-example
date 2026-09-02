/**
 * A short server-side log that the browser can read.
 *
 * Most of what goes wrong in an OIDC integration goes wrong on the server: a
 * logout POST comes back 400, a logout token fails signature verification, a
 * refresh is rejected. None of that reaches the page, so the symptom the user
 * sees is that a button did nothing — and finding the cause means having a
 * terminal open next to the browser.
 *
 * This keeps the last few of those events in memory so /api/auth/debug-log can
 * hand them to the page. It is a demo aid, not a logging library: entries are
 * per-process, capped, and lost on restart.
 */

export type LogLevel = 'info' | 'error';

export type LogEntry = {
  /** Monotonic within a process; also the cursor clients poll with. */
  id: number;
  at: number;
  level: LogLevel;
  event: string;
  detail?: string;
};

const MAX_ENTRIES = 100;

// Next.js re-evaluates modules on hot reload, which would otherwise give each
// route its own empty log. Hanging the state off globalThis keeps one.
const store = (globalThis as typeof globalThis & {
  __zeroDebugLog?: { entries: LogEntry[]; nextId: number };
}).__zeroDebugLog ??= { entries: [], nextId: 1 };

export function record(level: LogLevel, event: string, detail?: string): void {
  store.entries.push({ id: store.nextId++, at: Date.now(), level, event, detail });
  if (store.entries.length > MAX_ENTRIES) {
    store.entries.splice(0, store.entries.length - MAX_ENTRIES);
  }
  // Still write to stdout: `docker compose logs` remains the fuller record, and
  // this buffer only survives as long as the process does.
  const line = detail ? `[${event}] ${detail}` : `[${event}]`;
  if (level === 'error') console.error(line);
  else console.log(line);
}

export function entriesAfter(cursor: number): LogEntry[] {
  return store.entries.filter((e) => e.id > cursor);
}

/**
 * Renders an unknown thrown value as something worth reading. `String(err)` on
 * a plain object gives "[object Object]", which is how a useful error body ends
 * up invisible.
 */
export function describe(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}
