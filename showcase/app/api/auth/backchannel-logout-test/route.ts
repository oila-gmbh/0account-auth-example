import type { NextRequest } from "next/server"
import { NextResponse } from "next/server"
import { cookies } from "next/headers"
import { revokedSubs } from "@/app/lib/revokedSubs"

/**
 * GET /api/auth/backchannel-logout-test
 *
 * Local simulation of a back-channel logout for demo purposes. In production,
 * 0account calls POST /api/auth/backchannel-logout directly. This endpoint:
 *   1. Reads the current user's sub from the widget_session cookie.
 *   2. Adds that sub to the revokedSubs set.
 *
 * The profile page will detect the revocation on the next request and redirect
 * to /api/auth/widget-logout which clears the cookie.
 */
export async function GET(req: NextRequest) {
  const cookieStore = await cookies()
  const raw = cookieStore.get("widget_session")?.value

  if (!raw) {
    return NextResponse.redirect(new URL("/signin", req.nextUrl.origin))
  }

  try {
    const session = JSON.parse(raw) as { sub?: string }
    if (session.sub) {
      revokedSubs.add(session.sub)
      console.log("[backchannel-logout-test] simulated revocation for sub=%s", session.sub)
    }
  } catch {
    // malformed cookie — ignore
  }

  return NextResponse.redirect(new URL("/profile", req.nextUrl.origin))
}
