import { auth } from "@/auth"
import { cookies } from "next/headers"
import { NextResponse } from "next/server"
import { revokedSubs } from "@/app/lib/revokedSubs"

/**
 * GET /api/auth/status
 *
 * Lightweight session-check endpoint polled by protected pages every few seconds.
 * Returns 200 {"ok":true} when the session is valid, 401 otherwise.
 *
 * Handles both the Auth.js OIDC flow (JWT cookie) and the widget flow
 * (widget_session cookie), so a single endpoint covers all showcase users.
 */
export async function GET() {
  const [session, cookieStore] = await Promise.all([auth(), cookies()])

  // Auth.js (OIDC) session
  if (session) {
    if (session.user?.id && revokedSubs.has(session.user.id)) {
      return NextResponse.json({ error: "revoked" }, { status: 401 })
    }
    if (session.error === "RefreshAccessTokenError") {
      return NextResponse.json({ error: "token_expired" }, { status: 401 })
    }
    return NextResponse.json({ ok: true })
  }

  // Widget-flow session
  const raw = cookieStore.get("widget_session")?.value
  if (raw) {
    try {
      const s = JSON.parse(raw) as { sub?: string }
      if (s.sub) {
        if (revokedSubs.has(s.sub) || cookieStore.get("_bcl_revoked")?.value === "1") {
          return NextResponse.json({ error: "revoked" }, { status: 401 })
        }
        return NextResponse.json({ ok: true })
      }
    } catch {
      // malformed cookie — fall through
    }
  }

  return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
}
