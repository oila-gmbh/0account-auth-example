const express = require("express")
const session = require("express-session")
const { Issuer, generators } = require("openid-client")

const app = express()
app.use(express.json())
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    // In production, use a persistent session store (e.g. connect-redis)
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    },
  }),
)

const REDIRECT_URI = process.env.REDIRECT_URI || "http://localhost:3000/auth/callback"

let client

async function initClient() {
  const issuer = await Issuer.discover("https://v1.0account.com")
  client = new issuer.Client({
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    redirect_uris: [REDIRECT_URI],
    response_types: ["code"],
  })
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

// withAuth middleware — requires a valid session and proactively refreshes
// the access token when it is within 5 minutes of expiry.
async function withAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "not authenticated" })

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
  res.json({ userId: req.session.userId })
})

initClient().then(() =>
  app.listen(3000, () => console.log("Server running on http://localhost:3000")),
)
