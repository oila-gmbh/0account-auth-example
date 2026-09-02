/**
 * Sessions 0account has told us are over, by `sid`.
 *
 * Keyed by session, not by subject, for two reasons. A logout token names one
 * session, so revoking the subject would sign the user out of every device they
 * have — including the ones they did not touch. And a subject is permanent:
 * once added, the same person could never sign in again, because their next
 * sign-in carries the same subject and would be rejected on arrival. A `sid` is
 * minted per sign-in, so a new session is unaffected by an old revocation,
 * which is the property that makes this safe to keep in memory.
 *
 * Entries expire because nothing else removes them. A revoked session is dead
 * anyway once its tokens lapse, and holding the id forever only grows the set.
 *
 * A real deployment would put this in Redis or a database, shared across
 * instances rather than living in one process.
 */

import { record } from './debugLog';

/** Comfortably longer than any token issued for that session stays valid. */
const RETENTION_MS = 24 * 60 * 60 * 1000;

const store = (globalThis as typeof globalThis & {
  __zeroRevokedSessions?: Map<string, number>;
}).__zeroRevokedSessions ??= new Map<string, number>();

function prune(now: number): void {
  for (const [sid, revokedAt] of store) {
    if (now - revokedAt > RETENTION_MS) store.delete(sid);
  }
}

export function revokeSession(sid: string): void {
  const now = Date.now();
  prune(now);
  store.set(sid, now);
  record('info', 'session-revoked', `sid=${sid} — the next status poll will sign this browser out`);
}

export function isSessionRevoked(sid: string | undefined): boolean {
  if (!sid) return false;
  prune(Date.now());
  return store.has(sid);
}
