import type { NextRequest } from "next/server"
import { NextResponse } from "next/server"
import { auth } from "@/auth"
import { revokedSubs } from "@/app/lib/revokedSubs"

/**
 * GET /api/auth/backchannel-logout-test
 *
 * Simulates what happens when the user ends this session from their phone.
 *
 * In production 0account POSTs a signed logout token to
 * /api/auth/backchannel-logout. This endpoint fakes the effect of that call
 * locally, so the demo can show the consequence without a second device: it
 * marks the current subject revoked, and the poller notices within seconds.
 */
export async function GET(req: NextRequest) {
  const session = await auth()

  if (!session?.user?.id) {
    return NextResponse.redirect(new URL("/signin", req.nextUrl.origin))
  }

  revokedSubs.add(session.user.id)
  console.log("[backchannel-logout-test] simulated revocation for sub=%s", session.user.id)

  return NextResponse.redirect(new URL("/profile", req.nextUrl.origin))
}
