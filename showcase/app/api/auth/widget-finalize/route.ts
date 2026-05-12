import type { NextRequest } from "next/server"
import { NextResponse } from "next/server"
import {
  discovery,
  authorizationCodeGrant,
  fetchUserInfo,
  skipStateCheck,
  type Configuration,
} from "openid-client"

// Cache the discovered server metadata across requests (singleton per worker)
let _config: Configuration | undefined

async function getConfig(): Promise<Configuration> {
  if (!_config) {
    _config = await discovery(
      new URL("https://v1.0account.com"),
      process.env.CLIENT_ID!,
      process.env.CLIENT_SECRET!,
    )
  }
  return _config
}

// Called by the <zero-account> widget after the user approves on their mobile app.
// The widget POSTs { code, code_verifier, state, nonce, redirect_uri } as JSON.
// We exchange the code for tokens and store a minimal session cookie.
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null)
  const { code, code_verifier, state, redirect_uri } = (body ?? {}) as Record<string, string>

  if (!code || !code_verifier || !redirect_uri) {
    return NextResponse.json(
      { error: "missing required fields: code, code_verifier, redirect_uri" },
      { status: 400 },
    )
  }

  try {
    const config = await getConfig()

    // openid-client reads the code from the URL search params, so we build a
    // synthetic callback URL matching the widget's redirect-uri attribute.
    const callbackUrl = new URL(redirect_uri)
    callbackUrl.searchParams.set("code", code)
    if (state) callbackUrl.searchParams.set("state", state)

    const tokens = await authorizationCodeGrant(config, callbackUrl, {
      pkceCodeVerifier: code_verifier,
      expectedState: skipStateCheck,
    })

    const claims = tokens.claims()
    if (!claims?.sub) throw new Error("id_token missing sub claim")

    const userInfo = await fetchUserInfo(config, tokens.access_token!, claims.sub)
    // TODO: upsert user into your database by userInfo.sub

    const response = NextResponse.json({ success: true })
    response.cookies.set(
      "widget_session",
      JSON.stringify({
        sub: userInfo.sub,
        email: userInfo.email ?? "",
        name: (userInfo.name as string | undefined) ?? "",
        idToken: tokens.id_token ?? "",
      }),
      {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        maxAge: 30 * 24 * 60 * 60,
      },
    )
    return response
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    console.error("[widget-finalize] token exchange failed:", message)
    return NextResponse.json({ error: "token exchange failed", detail: message }, { status: 401 })
  }
}
