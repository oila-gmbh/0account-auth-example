import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { auth } from '@/auth';
import { revokeSession } from '@/app/lib/revokedSessions';
import { record } from '@/app/lib/debugLog';

/**
 * GET /api/auth/backchannel-logout-test
 *
 * Fakes the effect of 0account calling the back-channel logout URI, so the
 * consequence can be seen without a second device — and, more usefully, on
 * localhost, which a real logout token can never reach.
 *
 * It marks this session revoked exactly as the real handler would. What it does
 * not do is prove the real path works: that needs a public URL registered as
 * the app's backchannel logout URI.
 */
export async function GET(req: NextRequest) {
  const session = await auth();

  if (!session) {
    return NextResponse.redirect(new URL('/signin', req.nextUrl.origin));
  }
  if (!session.sid) {
    record('error', 'backchannel-logout-test', 'this session has no sid, so there is nothing to revoke');
    return NextResponse.redirect(new URL('/profile', req.nextUrl.origin));
  }

  revokeSession(session.sid);
  record('info', 'backchannel-logout-test', `simulated a logout token for sid=${session.sid}`);

  return NextResponse.redirect(new URL('/profile', req.nextUrl.origin));
}
