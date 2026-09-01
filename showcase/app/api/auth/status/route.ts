import { auth } from "@/auth"
import { NextResponse } from "next/server"
import { revokedSubs } from "@/app/lib/revokedSubs"

/**
 * GET /api/auth/status
 *
 * Lightweight session-check endpoint polled by protected pages every few seconds.
 * Returns 200 {"ok":true} when the session is valid, 401 otherwise.
 *
 * Reads the Auth.js session and reports whether it is still good.
 */
export async function GET() {
  const session = await auth()

  if (session) {
    if (session.user?.id && revokedSubs.has(session.user.id)) {
      return NextResponse.json({ error: "revoked" }, { status: 401 })
    }
    if (session.error === "RefreshAccessTokenError") {
      return NextResponse.json({ error: "token_expired" }, { status: 401 })
    }
    return NextResponse.json({ ok: true })
  }

  return NextResponse.json({ error: "unauthenticated" }, { status: 401 })
}
