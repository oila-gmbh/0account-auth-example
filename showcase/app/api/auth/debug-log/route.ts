import { NextRequest, NextResponse } from 'next/server';
import { entriesAfter } from '@/app/lib/debugLog';

/**
 * GET /api/auth/debug-log?after=<id>
 *
 * Hands the page whatever the server has logged since the id it last saw.
 *
 * A demo aid. It exposes what this process did — token endpoint statuses,
 * rejected logout tokens — and nothing that identifies a user beyond the
 * subjects and session ids already visible on the profile page. Do not ship
 * anything like it.
 */
export async function GET(req: NextRequest) {
  const after = Number(req.nextUrl.searchParams.get('after') ?? 0);
  return NextResponse.json({ entries: entriesAfter(Number.isFinite(after) ? after : 0) });
}
