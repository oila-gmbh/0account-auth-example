import type { NextRequest } from 'next/server';
import { signOut } from '@/auth';
import { record } from '@/app/lib/debugLog';

/**
 * GET /api/auth/oidc-logout?reason=<why>
 *
 * Clears the local session and says on the way out why it went. Reached when
 * something other than the user ended the session — the poller noticing a
 * revocation, or a refresh token that no longer works — so landing back on
 * /signin with no explanation would look like the site simply logged them out
 * for no reason.
 */
const REASONS: Record<string, string> = {
  revoked: 'SessionEndedElsewhere',
  token_expired: 'SessionExpired',
};

export async function GET(req: NextRequest) {
  const reason = req.nextUrl.searchParams.get('reason') ?? '';
  const code = REASONS[reason];

  if (code) {
    // signOut fires the RP-initiated logout below, and 0account will refuse it
    // when the session is already gone — which is the normal case here. Said
    // ahead of time so the rejection that follows does not read as a new fault.
    record('info', 'local-signout', `${reason}: clearing the local session; 0account may already have ended it`);
  }

  await signOut({ redirectTo: code ? `/signin?error=${code}` : '/signin' });
}
