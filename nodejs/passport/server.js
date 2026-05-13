const crypto = require("crypto")
const express = require("express")
const session = require("express-session")
const passport = require("passport")

const app = express()

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
app.use(passport.initialize())
app.use(passport.session())

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
      res.redirect("/dashboard")
    })
  } catch (err) {
    console.error("[passport] callback error:", err)
    res.redirect("/")
  }
})

app.get("/auth/logout", (req, res) => {
  const idToken = req.user?.idToken
  req.logout((err) => {
    if (err) return res.status(500).send("logout error")
    req.session.destroy(async () => {
      if (idToken) {
        // Server-to-server: terminate the session on 0account's side without a browser redirect.
        await fetch(LOGOUT_URL, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ id_token_hint: idToken }),
        }).catch(() => {})
      }
      res.redirect("/")
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

// Protected route example
app.get("/dashboard", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/auth/login")
  res.json({ userId: req.user.id, email: req.user.email })
})

app.listen(3000, () => console.log("Server running on http://localhost:3000"))
