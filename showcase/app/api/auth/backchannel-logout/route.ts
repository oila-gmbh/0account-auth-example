import crypto from "crypto"
import { NextRequest, NextResponse } from "next/server"
import { revokedSubs } from "@/app/lib/revokedSubs"

let _jwksKey: crypto.KeyObject | null = null

async function getLogoutKey(): Promise<crypto.KeyObject> {
  if (_jwksKey) return _jwksKey
  const res = await fetch("https://v1.0account.com/.well-known/jwks.json", {
    next: { revalidate: 3600 },
  })
  const { keys } = (await res.json()) as { keys: Array<{ kty: string; crv: string; x: string }> }
  const k = keys.find((k) => k.kty === "OKP" && k.crv === "Ed25519")
  if (!k) throw new Error("Ed25519 key not found in JWKS")
  _jwksKey = crypto.createPublicKey({ key: k as crypto.JsonWebKey, format: "jwk" })
  return _jwksKey
}

async function verifyLogoutToken(rawToken: string): Promise<string> {
  const parts = rawToken.split(".")
  if (parts.length !== 3) throw new Error("malformed JWT")
  const sig = Buffer.from(parts[2], "base64url")
  const pubKey = await getLogoutKey()
  const valid = crypto.verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), pubKey, sig)
  if (!valid) throw new Error("invalid signature")
  const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString()) as {
    sub?: string
    events?: Record<string, unknown>
  }
  if (!claims.sub) throw new Error("missing sub")
  if (!claims.events?.["http://schemas.openid.net/event/backchannel-logout"])
    throw new Error("missing backchannel-logout event")
  return claims.sub
}

/**
 * POST /api/auth/backchannel-logout
 *
 * Receives a signed back-channel logout token from 0account when a user's
 * session is terminated elsewhere (e.g. from the 0account mobile app).
 * Register this URL as `backchannel_logout_uri` in your 0account app settings.
 */
export async function POST(req: NextRequest) {
  let rawToken: string | null = null

  const contentType = req.headers.get("content-type") ?? ""
  if (contentType.includes("application/x-www-form-urlencoded")) {
    const body = await req.formData()
    rawToken = body.get("logout_token") as string | null
  } else {
    const body = await req.json().catch(() => ({}))
    rawToken = (body as { logout_token?: string }).logout_token ?? null
  }

  if (!rawToken) {
    return new NextResponse("missing logout_token", { status: 400 })
  }

  try {
    const sub = await verifyLogoutToken(rawToken)
    revokedSubs.add(sub)
    console.log("[backchannel-logout] revoked sub=%s", sub)
    return new NextResponse(null, { status: 200 })
  } catch (err) {
    console.error("[backchannel-logout] invalid token:", (err as Error).message)
    return new NextResponse("invalid logout_token", { status: 400 })
  }
}
