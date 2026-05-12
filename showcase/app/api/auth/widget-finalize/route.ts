import type { NextRequest } from "next/server"
import { NextResponse } from "next/server"

// Cache the OIDC endpoint URLs discovered from the server metadata (singleton per worker).
let _endpoints: { token: string; userinfo: string } | undefined

async function getEndpoints() {
  if (!_endpoints) {
    const res = await fetch("https://v1.0account.com/.well-known/openid-configuration")
    if (!res.ok) throw new Error(`OIDC discovery failed: ${res.status}`)
    const doc = await res.json()
    _endpoints = { token: doc.token_endpoint, userinfo: doc.userinfo_endpoint }
  }
  return _endpoints
}

// Called by the <zero-account> widget after the user approves on their mobile app.
// The widget POSTs { code, code_verifier, state, nonce, redirect_uri } as JSON.
// We exchange the code for tokens using RFC 6749 §4.1.3 + RFC 7636 §4.5 (PKCE).
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null)
  const { code, code_verifier, redirect_uri } = (body ?? {}) as Record<string, string>

  if (!code || !code_verifier || !redirect_uri) {
    return NextResponse.json(
      { error: "missing required fields: code, code_verifier, redirect_uri" },
      { status: 400 },
    )
  }

  try {
    const { token: tokenEndpoint, userinfo: userinfoEndpoint } = await getEndpoints()

    // Exchange authorization code for tokens (client_secret_post per 0account docs).
    const tokenRes = await fetch(tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri,
        code_verifier,
        client_id: process.env.NEXT_PUBLIC_CLIENT_ID!,
        client_secret: process.env.CLIENT_SECRET!,
      }),
    })

    const tokenData = await tokenRes.json()
    if (!tokenRes.ok || tokenData.error) {
      console.error("[widget-finalize] token exchange error:", JSON.stringify(tokenData))
      return NextResponse.json(
        { error: "token exchange failed", detail: tokenData.error_description ?? tokenData.error },
        { status: 401 },
      )
    }

    // Fetch user info using the access token.
    const userinfoRes = await fetch(userinfoEndpoint, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    })
    const userInfo = await userinfoRes.json()
    // TODO: upsert user into your database by userInfo.sub

    const response = NextResponse.json({ success: true })
    response.cookies.set(
      "widget_session",
      JSON.stringify({
        sub: userInfo.sub,
        email: userInfo.email ?? "",
        name: userInfo.name ?? "",
        idToken: tokenData.id_token ?? "",
      }),
      { httpOnly: true, sameSite: "lax", path: "/", maxAge: 30 * 24 * 60 * 60 },
    )
    return response
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    console.error("[widget-finalize] unexpected error:", message)
    return NextResponse.json({ error: "internal server error" }, { status: 500 })
  }
}
