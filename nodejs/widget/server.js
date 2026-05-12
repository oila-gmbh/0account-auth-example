const express = require("express")
const session = require("express-session")

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
  req.session.idToken = tokens.id_token
  req.session.accessToken = tokens.access_token
  req.session.refreshToken = tokens.refresh_token
  req.session.expiresAt = Math.floor(Date.now() / 1000) + tokens.expires_in

  res.json({ success: true })
})

// GET /auth/logout
app.get("/auth/logout", (req, res) => {
  const idToken = req.session.idToken
  req.session.destroy(async () => {
    if (idToken) {
      // Server-to-server: terminate the session on 0account's side without a browser redirect.
      await fetch("https://v1.0account.com/oauth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ id_token_hint: idToken }),
      }).catch(() => {})
    }
    res.redirect("/")
  })
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
