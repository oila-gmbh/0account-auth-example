'use client';

import { useSearchParams } from 'next/navigation';
import { useState } from 'react';

/**
 * Shows what went wrong, where the person can see it.
 *
 * Auth.js reports failures by redirecting with ?error=<code> and writing the
 * detail to the server log. A page that ignores the parameter therefore looks
 * like it simply did nothing, and the only way to find out otherwise is to have
 * a terminal open — which is exactly the situation someone integrating for the
 * first time is not in.
 *
 * The codes are short and unhelpful on their own, so each is translated into
 * the thing that is actually wrong and the thing to do about it.
 */
const MESSAGES: Record<string, { title: string; detail: string }> = {
  Configuration: {
    title: 'Server configuration problem',
    detail:
      'Usually a missing AUTH_SECRET or an untrusted host. Auth.js will not build ' +
      'callback URLs for a host it has not been told to trust — set trustHost, or ' +
      'AUTH_TRUST_HOST=true. Check the server log for the underlying error.',
  },
  OAuthCallback: {
    title: 'The callback was rejected',
    detail:
      'Most often the redirect URI is not registered on the app. Auth.js uses ' +
      '/api/auth/callback/0account, which is not the same path the other examples use.',
  },
  OAuthSignin: {
    title: 'Could not start sign-in',
    detail:
      'The provider could not be reached, or discovery failed. Check that ' +
      'https://v1.0account.com/.well-known/openid-configuration is reachable from here.',
  },
  OAuthAccountNotLinked: {
    title: 'That account is already linked elsewhere',
    detail: 'This email is already associated with a different sign-in method.',
  },
  AccessDenied: {
    title: 'Sign-in was declined',
    detail: 'The request was declined in the 0account app, or it expired before it was approved.',
  },
  Verification: {
    title: 'That link is no longer valid',
    detail: 'It expired or had already been used. Start again.',
  },
  // Not Auth.js codes — ours, set when the poller notices the session is over.
  SessionEndedElsewhere: {
    title: 'This session was ended somewhere else',
    detail:
      'The session was terminated in the 0account app, and we were told about it ' +
      'over back-channel logout. Signing in again starts a new one.',
  },
  SessionExpired: {
    title: 'Your session expired',
    detail: 'The refresh token could not be exchanged for a new access token. Sign in again.',
  },
};

export default function AuthError() {
  const params = useSearchParams();
  const [dismissed, setDismissed] = useState(false);

  const code = params.get('error');
  if (!code || dismissed) return null;

  // An unrecognised code is still worth showing: the code itself is a lead, and
  // silence is worse than a message we cannot expand on.
  const { title, detail } = MESSAGES[code] ?? {
    title: 'Sign-in failed',
    detail: `The provider returned "${code}". Check the server log for detail.`,
  };

  return (
    <div
      role="alert"
      className="mb-6 rounded-xl border border-red-900/60 bg-red-950/40 px-4 py-3"
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-medium text-red-300">{title}</p>
          <p className="mt-1 text-xs leading-relaxed text-red-200/70">{detail}</p>
          <p className="mt-2 font-mono text-[11px] text-red-200/40">error={code}</p>
        </div>
        <button
          onClick={() => setDismissed(true)}
          aria-label="Dismiss"
          className="shrink-0 rounded-md px-2 py-1 text-red-300/60 transition-colors hover:bg-red-900/40 hover:text-red-200"
        >
          ✕
        </button>
      </div>
    </div>
  );
}
