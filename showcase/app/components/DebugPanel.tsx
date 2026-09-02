'use client';

import { useEffect, useRef, useState } from 'react';

/**
 * Everything that went wrong, on the page instead of in a terminal.
 *
 * Two sources feed it. The server log is polled from /api/auth/debug-log — that
 * is where a rejected logout token or a 400 from the token endpoint shows up,
 * and none of it would otherwise be visible to someone watching the browser.
 * The browser's own uncaught errors and rejected promises are captured here,
 * because a page that throws during render just stops, silently.
 *
 * It opens itself when something fails, on the theory that an error nobody sees
 * is the same as no error at all.
 */

type Entry = {
  id: number;
  at: number;
  level: 'info' | 'error';
  event: string;
  detail?: string;
  source: 'server' | 'browser';
};

const POLL_MS = 3000;

function time(at: number): string {
  return new Date(at).toLocaleTimeString(undefined, { hour12: false });
}

export default function DebugPanel() {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [open, setOpen] = useState(false);
  // Ref, not state: the poll closure would otherwise capture the value it was
  // created with and re-request the same entries forever.
  const cursor = useRef(0);
  const browserId = useRef(-1);

  const add = (entry: Entry) => setEntries((prev) => [...prev, entry].slice(-100));

  useEffect(() => {
    const onError = (e: ErrorEvent) =>
      add({
        id: browserId.current--,
        at: Date.now(),
        level: 'error',
        event: 'browser-error',
        detail: `${e.message} (${e.filename}:${e.lineno})`,
        source: 'browser',
      });

    const onRejection = (e: PromiseRejectionEvent) =>
      add({
        id: browserId.current--,
        at: Date.now(),
        level: 'error',
        event: 'unhandled-rejection',
        detail: String(e.reason instanceof Error ? e.reason.message : e.reason),
        source: 'browser',
      });

    window.addEventListener('error', onError);
    window.addEventListener('unhandledrejection', onRejection);

    let cancelled = false;
    const poll = async () => {
      try {
        const res = await fetch(`/api/auth/debug-log?after=${cursor.current}`);
        if (!res.ok) return;
        const { entries: fresh } = (await res.json()) as { entries: Omit<Entry, 'source'>[] };
        if (cancelled || fresh.length === 0) return;
        cursor.current = fresh[fresh.length - 1].id;
        fresh.forEach((e) => add({ ...e, source: 'server' }));
      } catch {
        // The server being unreachable is its own kind of answer; the next
        // tick will either recover or the page will have gone.
      }
    };

    poll();
    const timer = setInterval(poll, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
      window.removeEventListener('error', onError);
      window.removeEventListener('unhandledrejection', onRejection);
    };
  }, []);

  const errors = entries.filter((e) => e.level === 'error').length;

  // Open on the first failure, but never fight the user: once they close it, it
  // stays closed until they open it again.
  const lastError = useRef(0);
  const [dismissedAt, setDismissedAt] = useState(0);
  useEffect(() => {
    if (errors > lastError.current) {
      lastError.current = errors;
      if (errors > dismissedAt) setOpen(true);
    }
  }, [errors, dismissedAt]);

  if (entries.length === 0) return null;

  return (
    <div className="fixed bottom-0 right-0 z-50 m-3 w-[min(34rem,calc(100vw-1.5rem))] font-mono text-[11px]">
      <button
        onClick={() => {
          if (open) setDismissedAt(errors);
          setOpen((v) => !v);
        }}
        className="flex w-full items-center justify-between rounded-t-lg border border-zinc-800 bg-zinc-900 px-3 py-1.5 text-zinc-400 transition-colors hover:bg-zinc-800"
      >
        <span>
          server log
          {errors > 0 && <span className="ml-2 text-red-400">{errors} error{errors === 1 ? '' : 's'}</span>}
        </span>
        <span className="text-zinc-600">{open ? '▼' : '▲'}</span>
      </button>

      {open && (
        <div className="max-h-72 overflow-y-auto rounded-b-lg border border-t-0 border-zinc-800 bg-zinc-950/95 p-2">
          {entries
            .slice()
            .reverse()
            .map((e) => (
              <div
                key={`${e.source}-${e.id}`}
                className={`flex gap-2 border-b border-zinc-900 px-1 py-1 last:border-0 ${
                  e.level === 'error' ? 'text-red-300' : 'text-zinc-400'
                }`}
              >
                <span className="shrink-0 text-zinc-600">{time(e.at)}</span>
                <span className="shrink-0">{e.event}</span>
                {e.detail && <span className="break-all text-zinc-500">{e.detail}</span>}
              </div>
            ))}
        </div>
      )}
    </div>
  );
}
