const crypto = require("crypto")
const express = require("express")
const session = require("express-session")
const { Issuer, generators, custom } = require("openid-client")

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
}

function dashboardPage(userId, email, name) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard — openid-client</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#09090b;color:#fafafa;min-height:100vh;display:flex;align-items:center;justify-content:center}.card{background:#18181b;border:1px solid #27272a;border-radius:16px;padding:32px;width:360px}h1{font-size:1.125rem;font-weight:600;margin-bottom:20px}.row{display:flex;justify-content:space-between;gap:12px;background:#27272a66;border-radius:8px;padding:8px 12px;margin-bottom:8px}.label{font-size:.75rem;color:#a1a1aa;white-space:nowrap}.value{font-family:'SF Mono',monospace;font-size:.75rem;color:#e4e4e7;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px}.btn{display:block;margin-top:20px;padding:10px 16px;border:1px solid #3f3f46;background:transparent;color:#a1a1aa;border-radius:10px;font-size:.875rem;text-align:center;text-decoration:none;transition:background .15s}.btn:hover{background:#27272a;color:#e4e4e7}</style>
</head><body><div class="card">
<h1>Dashboard</h1>
<div class="row"><span class="label">User ID</span><span class="value">${esc(userId)}</span></div>
<div class="row"><span class="label">Email</span><span class="value">${esc(email)}</span></div>
<div class="row"><span class="label">Name</span><span class="value">${esc(name)}</span></div>
<a href="/auth/logout" class="btn">Sign out</a>
</div>
<script>(function(){var t=setInterval(async function(){try{var r=await fetch('/auth/status');if(r.status===401){clearInterval(t);window.location.href='/auth/login';}}catch(e){}},3000);})();</script>
</body></html>`
}

const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    // In production, use a persistent session store (e.g. connect-redis)
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: "lax",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    },
  }),
)

// CORS: allow the showcase origin to make credentialed fetch requests.
app.use((req, res, next) => {
  if (req.headers.origin === APP_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", APP_ORIGIN)
    res.setHeader("Access-Control-Allow-Credentials", "true")
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS")
    res.setHeader("Access-Control-Allow-Headers", "Content-Type")
  }
  if (req.method === "OPTIONS") return res.sendStatus(204)
  next()
})

const APP_ORIGIN = process.env.APP_ORIGIN || "http://localhost:3000"
const SELF_URL = process.env.SELF_URL || "http://localhost:8082"
const REDIRECT_URI = process.env.REDIRECT_URI || "http://localhost:3000/auth/callback"

let client

// revokedSubs tracks subjects whose sessions were revoked via back-channel logout.
// In production, use a shared store (e.g. Redis) across all server instances.
const revokedSubs = new Set()

let _jwksKey = null
async function getLogoutKey() {
  if (_jwksKey) return _jwksKey
  const res = await fetch("https://v1.0account.com/.well-known/jwks.json")
  const { keys } = await res.json()
  const k = keys.find((k) => k.kty === "OKP" && k.crv === "Ed25519")
  if (!k) throw new Error("Ed25519 key not found in JWKS")
  _jwksKey = crypto.createPublicKey({ key: k, format: "jwk" })
  return _jwksKey
}

async function verifyLogoutToken(rawToken) {
  const parts = rawToken.split(".")
  if (parts.length !== 3) throw new Error("malformed JWT")
  const sig = Buffer.from(parts[2], "base64url")
  const pubKey = await getLogoutKey()
  const valid = crypto.verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), pubKey, sig)
  if (!valid) throw new Error("invalid signature")
  const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString())
  if (!claims.sub) throw new Error("missing sub")
  if (!claims.events?.["http://schemas.openid.net/event/backchannel-logout"])
    throw new Error("missing backchannel-logout event")
  return claims.sub
}

async function initClient() {
  const issuer = await Issuer.discover("https://v1.0account.com")
  client = new issuer.Client({
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    redirect_uris: [REDIRECT_URI],
    response_types: ["code"],
    id_token_signed_response_alg: "EdDSA",
  })
  // Allow up to 10 seconds of clock drift between this server and the issuer.
  client[custom.clock_skew] = 10
}

app.get("/auth/login", (req, res) => {
  const state = generators.state()
  const verifier = generators.codeVerifier()
  const challenge = generators.codeChallenge(verifier)

  req.session.oauthState = state
  req.session.pkceVerifier = verifier

  res.redirect(
    client.authorizationUrl({
      scope: "openid profile email offline_access",
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    }),
  )
})

app.get("/auth/callback", async (req, res) => {
  try {
    const params = client.callbackParams(req)
    const tokenSet = await client.callback(REDIRECT_URI, params, {
      state: req.session.oauthState,
      code_verifier: req.session.pkceVerifier,
    })

    delete req.session.oauthState
    delete req.session.pkceVerifier

    const claims = tokenSet.claims()
    // claims.sub, claims.email, claims.given_name, claims.family_name
    // TODO: upsert user into your database by claims.sub

    req.session.userId = claims.sub
    req.session.email = claims.email ?? ""
    req.session.name = claims.name ?? `${claims.given_name ?? ""} ${claims.family_name ?? ""}`.trim()
    req.session.idToken = tokenSet.id_token
    req.session.accessToken = tokenSet.access_token
    req.session.refreshToken = tokenSet.refresh_token
    req.session.expiresAt = tokenSet.expires_at // Unix seconds

    // Clear any previously revoked entry for this subject on fresh login.
    revokedSubs.delete(claims.sub)

    res.redirect(`${APP_ORIGIN}/profile?url=${encodeURIComponent(SELF_URL)}`)
  } catch (err) {
    console.error("callback error:", err)
    res.status(401).send("Authentication failed")
  }
})

app.get("/auth/logout", async (req, res) => {
  const idToken = req.session.idToken
  const returnTo = req.query.return_to
  const safeReturn = typeof returnTo === "string" && returnTo.startsWith(APP_ORIGIN)
    ? returnTo : "/auth/login"
  await new Promise((resolve) => req.session.destroy(resolve))
  if (idToken) {
    await fetch("https://v1.0account.com/oauth/logout", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ id_token_hint: idToken }),
    }).catch(() => {})
  }
  res.redirect(safeReturn)
})

// withAuth middleware — requires a valid session, checks revocation, and proactively
// refreshes the access token when it is within 5 minutes of expiry.
async function withAuth(req, res, next) {
  if (!req.session.userId) return res.redirect("/auth/login")
  if (revokedSubs.has(req.session.userId)) {
    return req.session.destroy(() => res.redirect("/auth/login"))
  }

  const expiresIn = req.session.expiresAt * 1000 - Date.now()
  if (expiresIn < 5 * 60 * 1000 && req.session.refreshToken) {
    try {
      const tokenSet = await client.refresh(req.session.refreshToken)
      req.session.accessToken = tokenSet.access_token
      req.session.expiresAt = tokenSet.expires_at
      if (tokenSet.refresh_token) {
        req.session.refreshToken = tokenSet.refresh_token // accept rotated refresh token
      }
    } catch {
      return req.session.destroy(() => res.redirect("/auth/login"))
    }
  }
  next()
}

// Protected route — redirects to central profile
app.get("/dashboard", withAuth, (req, res) => {
  res.redirect(`${APP_ORIGIN}/profile?url=${encodeURIComponent(SELF_URL)}`)
})

app.get("/auth/me", withAuth, (req, res) => {
  res.json({
    userId: req.session.userId,
    email: req.session.email,
    name: req.session.name,
    integration: {
      name: "openid-client",
      language: "Node.js",
      flow: "oidc",
      library: "openid-client",
      url: SELF_URL,
    },
  })
})

app.get("/auth/status", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "unauthenticated" })
  if (revokedSubs.has(req.session.userId)) return res.status(401).json({ error: "revoked" })
  res.json({ ok: true })
})

// Back-channel logout endpoint — called by 0account when the user logs out elsewhere.
// Register this URI as backchannel_logout_uri in your 0account app settings.
app.post("/auth/backchannel-logout", async (req, res) => {
  const rawToken = req.body?.logout_token
  if (!rawToken) return res.status(400).send("missing logout_token")
  try {
    const sub = await verifyLogoutToken(rawToken)
    revokedSubs.add(sub)
    console.log("[openid-client] backchannel-logout: revoked sub=%s", sub)
    res.sendStatus(200)
  } catch (err) {
    console.error("[openid-client] backchannel-logout: invalid token:", err.message)
    res.status(400).send("invalid logout_token")
  }
})

initClient().then(() =>
  app.listen(3000, () => console.log("Server running on http://localhost:3000")),
)
