const crypto = require("crypto")
const express = require("express")
const session = require("express-session")
const passport = require("passport")

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
<title>Dashboard — passport</title>
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

const APP_ORIGIN = process.env.APP_ORIGIN || "http://localhost:3000"
const SELF_URL = process.env.SELF_URL || "http://localhost:8081"

const ISSUER = "https://v1.0account.com"
const AUTHORIZATION_URL = `${ISSUER}/oauth/authorize`
const TOKEN_URL = `${ISSUER}/oauth/token`
const USERINFO_URL = `${ISSUER}/oauth/userinfo`
const LOGOUT_URL = `${ISSUER}/oauth/logout`

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    // In production, use a persistent session store (e.g. connect-redis)
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    },
  }),
)
app.use(express.urlencoded({ extended: false }))
app.use(passport.initialize())
app.use(passport.session())

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

// Passport serializes the full user object into the session.
// In production, store only user.id and re-fetch the user on each request.
passport.serializeUser((user, done) => done(null, user))
passport.deserializeUser((user, done) => done(null, user))

// PKCE helpers (RFC 7636)
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString("base64url")
}
function generateCodeChallenge(verifier) {
  return crypto.createHash("sha256").update(verifier).digest("base64url")
}

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

app.get("/auth/login", (req, res) => {
  const state = crypto.randomBytes(16).toString("base64url")
  const nonce = crypto.randomBytes(16).toString("base64url")
  const verifier = generateCodeVerifier()
  const challenge = generateCodeChallenge(verifier)

  // Persist CSRF state + PKCE verifier in the session for callback validation.
  req.session.oidcState = state
  req.session.oidcNonce = nonce
  req.session.oidcVerifier = verifier

  const params = new URLSearchParams({
    response_type: "code",
    client_id: process.env.CLIENT_ID,
    redirect_uri: process.env.REDIRECT_URI || "http://localhost:3000/auth/callback",
    scope: "openid profile email offline_access",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  })

  // Explicitly save before redirecting — avoids a race condition where the
  // async MemoryStore callback hasn't fired before the browser follows the redirect.
  req.session.save((err) => {
    if (err) return res.status(500).send("session error")
    res.redirect(`${AUTHORIZATION_URL}?${params}`)
  })
})

app.get("/auth/callback", async (req, res) => {
  if (req.query.error) {
    console.error("[passport] 0account error:", req.query.error, req.query.error_description)
    return res.redirect("/")
  }

  if (!req.query.code || req.query.state !== req.session.oidcState) {
    return res.status(400).send("invalid state or missing code")
  }

  const { code } = req.query
  const { oidcVerifier: verifier, oidcNonce: nonce } = req.session
  const redirectUri = process.env.REDIRECT_URI || "http://localhost:3000/auth/callback"

  try {
    // Exchange authorization code for tokens using client_secret_post + PKCE verifier.
    const tokenRes = await fetch(TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        code_verifier: verifier,
      }),
    })

    if (!tokenRes.ok) {
      const err = await tokenRes.json().catch(() => ({}))
      console.error("[passport] token exchange failed:", err)
      return res.redirect("/")
    }

    const tokens = await tokenRes.json()

    // Decode ID token claims (note: signature verification is omitted for brevity;
    // use a library like jose or jsonwebtoken in production).
    const idTokenClaims = JSON.parse(Buffer.from(tokens.id_token.split(".")[1], "base64url").toString())
    if (idTokenClaims.nonce !== nonce) {
      return res.status(400).send("nonce mismatch")
    }

    // Fetch user profile from the userinfo endpoint.
    const userInfoRes = await fetch(USERINFO_URL, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    })
    const userInfo = await userInfoRes.json()

    const user = {
      id: userInfo.sub,
      email: userInfo.email,
      displayName: userInfo.name,
      idToken: tokens.id_token,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
    }

    // req.login() uses Passport's session serialization to persist the user.
    req.login(user, (err) => {
      if (err) return res.status(500).send("session error")
      // Clear any previously revoked entry for this subject on fresh login.
      revokedSubs.delete(user.id)
      res.redirect(`${APP_ORIGIN}/profile?url=${encodeURIComponent(SELF_URL)}`)
    })
  } catch (err) {
    console.error("[passport] callback error:", err)
    res.redirect("/")
  }
})

app.get("/auth/logout", (req, res) => {
  const idToken = req.user?.idToken
  const returnTo = req.query.return_to
  const safeReturn = typeof returnTo === "string" && returnTo.startsWith(APP_ORIGIN)
    ? returnTo : "/auth/login"
  req.logout((err) => {
    if (err) return res.status(500).send("logout error")
    req.session.destroy(async () => {
      if (idToken) {
        await fetch(LOGOUT_URL, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ id_token_hint: idToken }),
        }).catch(() => {})
      }
      res.redirect(safeReturn)
    })
  })
})

// refreshAccessToken — call when req.user.accessToken is near expiry.
// Update req.session.passport.user with the new tokens afterwards.
async function refreshAccessToken(refreshToken) {
  const response = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
    }),
  })
  if (!response.ok) throw new Error("refresh failed")
  return response.json()
}

// Protected route example — redirects to central profile
app.get("/dashboard", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/auth/login")
  if (revokedSubs.has(req.user.id)) {
    return req.session.destroy(() => res.redirect("/auth/login"))
  }
  res.redirect(`${APP_ORIGIN}/profile?url=${encodeURIComponent(SELF_URL)}`)
})

app.get("/auth/me", (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: "not authenticated" })
  if (revokedSubs.has(req.user.id)) return res.status(401).json({ error: "revoked" })
  res.json({
    userId: req.user.id,
    email: req.user.email,
    name: req.user.displayName,
    integration: {
      name: "Passport.js",
      language: "Node.js",
      flow: "oidc",
      library: "passport-openidconnect",
      url: SELF_URL,
    },
  })
})

app.get("/auth/status", (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: "unauthenticated" })
  if (revokedSubs.has(req.user.id)) return res.status(401).json({ error: "revoked" })
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
    console.log("[passport] backchannel-logout: revoked sub=%s", sub)
    res.sendStatus(200)
  } catch (err) {
    console.error("[passport] backchannel-logout: invalid token:", err.message)
    res.status(400).send("invalid logout_token")
  }
})

app.listen(3000, () => console.log("Server running on http://localhost:3000"))
