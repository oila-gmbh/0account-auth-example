import type { NextRequest } from "next/server"
import { NextResponse } from "next/server"

type TokenResponse = {
  access_token: string
  id_token: string
  refresh_token: string
  expires_in: number
}

type UserInfo = {
  sub: string
  email: string
  name: string
}

// Called by the <zero-account> widget after the user approves on their mobile app.
// Exchanges the authorization code for tokens and stores a minimal session cookie.
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null)
  const { code, code_verifier, redirect_uri } = (body ?? {}) as Record<string, string>

  if (!code || !code_verifier) {
    return NextResponse.json({ error: "missing code or code_verifier" }, { status: 400 })
  }

  // Exchange authorization code for tokens
  const tokenRes = await fetch("https://v1.0account.com/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      code_verifier,
      redirect_uri: redirect_uri ?? "",
      client_id: process.env.CLIENT_ID!,
      client_secret: process.env.CLIENT_SECRET!,
    }),
  })
  if (!tokenRes.ok) {
    return NextResponse.json({ error: "token exchange failed" }, { status: 401 })
  }
  const tokens = (await tokenRes.json()) as TokenResponse

  // Fetch user info to get the subject (user ID)
  const userRes = await fetch("https://v1.0account.com/oauth/userinfo", {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  })
  if (!userRes.ok) {
    return NextResponse.json({ error: "failed to fetch user info" }, { status: 500 })
  }
  const user = (await userRes.json()) as UserInfo
  // TODO: upsert user into your database by user.sub

  // Store user info and id_token in a server-only httpOnly cookie.
  // In production, sign or encrypt this cookie and/or use a server-side session store.
  const response = NextResponse.json({ success: true })
  response.cookies.set(
    "widget_session",
    JSON.stringify({
      sub: user.sub,
      email: user.email,
      name: user.name,
      // id_token is used for server-to-server logout — not a secret.
      idToken: tokens.id_token,
    }),
    {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 30 * 24 * 60 * 60,
    },
  )
  return response
}
