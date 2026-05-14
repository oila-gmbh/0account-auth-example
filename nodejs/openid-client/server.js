const crypto = require("crypto")
const express = require("express")
const session = require("express-session")
const { Issuer, generators, custom } = require("openid-client")

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
    req.session.idToken = tokenSet.id_token
    req.session.accessToken = tokenSet.access_token
    req.session.refreshToken = tokenSet.refresh_token
    req.session.expiresAt = tokenSet.expires_at // Unix seconds

    // Clear any previously revoked entry for this subject on fresh login.
    revokedSubs.delete(claims.sub)

    res.redirect("/dashboard")
  } catch (err) {
    console.error("callback error:", err)
    res.status(401).send("Authentication failed")
  }
})

app.get("/auth/logout", async (req, res) => {
  const idToken = req.session.idToken
  await new Promise((resolve) => req.session.destroy(resolve))
  if (idToken) {
    // Server-to-server: terminate the session on 0account's side without a browser redirect.
    await fetch("https://v1.0account.com/oauth/logout", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ id_token_hint: idToken }),
    }).catch(() => {}) // best-effort; local session already destroyed
  }
  res.redirect("/")
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

// Protected route example
app.get("/dashboard", withAuth, (req, res) => {
  res.type("html").send(`<!DOCTYPE html><html><head><title>Dashboard</title></head><body>
<h1>Dashboard</h1>
<p>Logged in as: <strong>${req.session.userId}</strong></p>
<p><a href="/auth/logout">Sign out</a></p>
</body></html>`)
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

app.get("/", (req, res) => {
  res.type("html").send(`<!DOCTYPE html><html><head><title>openid-client example</title></head><body>
<h1>0account openid-client example</h1>
<p><a href="/auth/login">Sign in</a></p>
</body></html>`)
})

initClient().then(() =>
  app.listen(3000, () => console.log("Server running on http://localhost:3000")),
)
