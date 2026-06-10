const crypto = require("crypto")
const express = require("express")
const session = require("express-session")

const app = express()

const APP_ORIGIN = process.env.APP_ORIGIN || "http://localhost:3000"
const SELF_URL = process.env.SELF_URL || "http://localhost:8086"

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
      secure: process.env.NODE_ENV === "production",
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
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    res.setHeader("Access-Control-Allow-Headers", "Content-Type")
  }
  if (req.method === "OPTIONS") return res.sendStatus(204)
  next()
})
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

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
}

function loginPage() {
  const clientId = process.env.CLIENT_ID ?? ""
  const redirectUri = process.env.REDIRECT_URI ?? "http://localhost:3000/"
  const profileUrl = `${APP_ORIGIN}/profile?url=${encodeURIComponent(SELF_URL)}`
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in — widget</title>
<script src="https://unpkg.com/@0account/web@1.3.4/dist/0account-web.umd.cjs"></script>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#09090b;color:#fafafa;min-height:100vh;display:flex;align-items:center;justify-content:center}</style>
</head><body>
<zero-account
  app-id="${esc(clientId)}"
  redirect-uri="${esc(redirectUri)}"
  finalize-uri="/auth/finalize"
  scope="openid profile email offline_access"
  with-button>
</zero-account>
<script>
  document.querySelector('zero-account').addEventListener('0account-authenticated', function() {
    window.location.href = '${esc(profileUrl)}'
  })
</script>
</body></html>`
}

function dashboardPage(userId, email, name) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard — widget</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#09090b;color:#fafafa;min-height:100vh;display:flex;align-items:center;justify-content:center}.card{background:#18181b;border:1px solid #27272a;border-radius:16px;padding:32px;width:360px}h1{font-size:1.125rem;font-weight:600;margin-bottom:20px}.row{display:flex;justify-content:space-between;gap:12px;background:#27272a66;border-radius:8px;padding:8px 12px;margin-bottom:8px}.label{font-size:.75rem;color:#a1a1aa;white-space:nowrap}.value{font-family:'SF Mono',monospace;font-size:.75rem;color:#e4e4e7;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px}.btn{display:block;margin-top:20px;padding:10px 16px;border:1px solid #3f3f46;background:transparent;color:#a1a1aa;border-radius:10px;font-size:.875rem;text-align:center;text-decoration:none;transition:background .15s}.btn:hover{background:#27272a;color:#e4e4e7}</style>
</head><body><div class="card">
<h1>Dashboard</h1>
<div class="row"><span class="label">User ID</span><span class="value">${esc(userId)}</span></div>
<div class="row"><span class="label">Email</span><span class="value">${esc(email)}</span></div>
<div class="row"><span class="label">Name</span><span class="value">${esc(name)}</span></div>
<a href="/auth/logout" class="btn">Sign out</a>
</div>
<script>(function(){var t=setInterval(async function(){try{var r=await fetch('/auth/status');if(r.status===401){clearInterval(t);window.location.href='/';}}catch(e){}},3000);})();</script>
</body></html>`
}

// GET / — show login page; redirect to central profile if already authenticated
app.get("/", (req, res) => {
  if (req.session.userId && !revokedSubs.has(req.session.userId)) {
    return res.redirect(`${APP_ORIGIN}/profile?url=${encodeURIComponent(SELF_URL)}`)
  }
  res.type("html").send(loginPage())
})

// GET /dashboard — redirect to central profile (backward compat)
app.get("/dashboard", (req, res) => {
  if (!req.session.userId || revokedSubs.has(req.session.userId)) {
    return res.redirect("/")
  }
  res.redirect(`${APP_ORIGIN}/profile?url=${encodeURIComponent(SELF_URL)}`)
})

// POST /auth/finalize — called by the widget after the user approves
app.post("/auth/finalize", async (req, res) => {
  const { code, code_verifier, redirect_uri } = req.body
  if (!code || !code_verifier) {
    return res.status(400).json({ error: "missing code or code_verifier" })
  }

  // Exchange authorization code for tokens
  const tokenRes = await fetch("https://v1.0account.com/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      code_verifier,
      redirect_uri,
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
    }),
  })
  if (!tokenRes.ok) return res.status(401).json({ error: "token exchange failed" })

  const tokens = await tokenRes.json()
  // tokens.access_token, tokens.id_token, tokens.refresh_token, tokens.expires_in

  // Fetch user info to get the subject (user ID)
  const userRes = await fetch("https://v1.0account.com/oauth/userinfo", {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  })
  if (!userRes.ok) return res.status(500).json({ error: "failed to fetch user info" })

  const user = await userRes.json()
  // user.sub, user.email, user.name
  // TODO: upsert user into your database by user.sub

  req.session.userId = user.sub
  req.session.email = user.email ?? ""
  req.session.name = user.name ?? ""
  req.session.idToken = tokens.id_token
  req.session.accessToken = tokens.access_token
  req.session.refreshToken = tokens.refresh_token
  req.session.expiresAt = Math.floor(Date.now() / 1000) + tokens.expires_in

  // Clear any previously revoked entry for this subject on fresh login.
  revokedSubs.delete(user.sub)

  res.json({ success: true })
})

// GET /auth/me — session info + integration metadata for the central profile page
app.get("/auth/me", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "not authenticated" })
  if (revokedSubs.has(req.session.userId)) return res.status(401).json({ error: "revoked" })
  res.json({
    userId: req.session.userId,
    email: req.session.email,
    name: req.session.name,
    integration: {
      name: "Widget",
      language: "Node.js",
      flow: "widget",
      library: "@0account/web",
      url: SELF_URL,
    },
  })
})

// GET /auth/logout
app.get("/auth/logout", (req, res) => {
  const idToken = req.session.idToken
  const returnTo = req.query.return_to
  const safeReturn = typeof returnTo === "string" && returnTo.startsWith(APP_ORIGIN)
    ? returnTo : "/"
  req.session.destroy(async () => {
    if (idToken) {
      await fetch("https://v1.0account.com/oauth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ id_token_hint: idToken }),
      }).catch(() => {})
    }
    res.redirect(safeReturn)
  })
})

// POST /auth/backchannel-logout — called by 0account when the user logs out remotely.
// Register this URI as backchannel_logout_uri in your 0account app settings.
app.post("/auth/backchannel-logout", async (req, res) => {
  const rawToken = req.body?.logout_token
  try {
    const sub = await verifyLogoutToken(rawToken)
    revokedSubs.add(sub)
    console.log("[widget] backchannel-logout: revoked sub=%s", sub)
    res.sendStatus(200)
  } catch (err) {
    console.error("[widget] backchannel-logout: invalid token:", err.message)
    res.sendStatus(400)
  }
})

app.get("/auth/status", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "unauthenticated" })
  if (revokedSubs.has(req.session.userId)) return res.status(401).json({ error: "revoked" })
  res.json({ ok: true })
})

// POST /auth/refresh
app.post("/auth/refresh", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "not authenticated" })
  if (!req.session.refreshToken) return res.status(401).json({ error: "no refresh token" })

  const tokenRes = await fetch("https://v1.0account.com/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: req.session.refreshToken,
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
    }),
  })
  if (!tokenRes.ok) return res.status(401).json({ error: "refresh failed" })

  const tokens = await tokenRes.json()
  req.session.accessToken = tokens.access_token
  req.session.expiresAt = Math.floor(Date.now() / 1000) + tokens.expires_in
  if (tokens.refresh_token) {
    req.session.refreshToken = tokens.refresh_token // accept rotated refresh token
  }

  res.json({ success: true })
})

app.listen(3000, () => console.log("Server running on http://localhost:3000"))
