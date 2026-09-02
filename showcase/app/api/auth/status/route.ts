import { auth } from '@/auth';
import { NextResponse } from 'next/server';
import { isSessionRevoked } from '@/app/lib/revokedSessions';

/**
 * GET /api/auth/status
 *
 * Polled by protected pages. 200 while the session is still good, 401 once it
 * is not — which is how a logout that happened on the phone becomes a redirect
 * in a browser that was never told anything.
 *
 * The 401 body names the reason so the page can say which of the three it was.
 */
export async function GET() {
  const session = await auth();

  if (!session) {
    return NextResponse.json({ error: 'unauthenticated' }, { status: 401 });
  }
  if (isSessionRevoked(session.sid)) {
    return NextResponse.json({ error: 'revoked' }, { status: 401 });
  }
  if (session.error === 'RefreshAccessTokenError') {
    return NextResponse.json({ error: 'token_expired' }, { status: 401 });
  }

  return NextResponse.json({ ok: true });
}
