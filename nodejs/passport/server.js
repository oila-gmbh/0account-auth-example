const express = require("express")
const session = require("express-session")
const passport = require("passport")
const { Strategy } = require("passport-openidconnect")

const app = express()

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
app.use(passport.initialize())
app.use(passport.session())

passport.use(
  new Strategy(
    {
      issuer: "https://v1.0account.com",
      authorizationURL: "https://v1.0account.com/oauth/authorize",
      tokenURL: "https://v1.0account.com/oauth/token",
      userInfoURL: "https://v1.0account.com/oauth/userinfo",
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/callback",
      scope: ["openid", "profile", "email", "offline_access"],
      pkce: true, // requires passport-openidconnect v0.1.0+
    },
    (issuer, profile, context, idToken, accessToken, refreshToken, done) => {
      // profile.id, profile.emails[0].value, profile.displayName
      // TODO: upsert user into your database by profile.id
      return done(null, {
        id: profile.id,
        email: profile.emails?.[0]?.value,
        displayName: profile.displayName,
        idToken,
        accessToken,
        refreshToken,
      })
    },
  ),
)

passport.serializeUser((user, done) => done(null, user))
passport.deserializeUser((user, done) => done(null, user))

app.get("/auth/login", passport.authenticate("openidconnect"))

app.get(
  "/auth/callback",
  passport.authenticate("openidconnect", { failureRedirect: "/" }),
  (req, res) => res.redirect("/dashboard"),
)

app.get("/auth/logout", (req, res) => {
  const idToken = req.user?.idToken
  req.logout((err) => {
    if (err) return res.status(500).send("logout error")
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
})

// refreshAccessToken — call when req.user.accessToken is near expiry.
// Update req.session.passport.user with the new tokens afterwards.
async function refreshAccessToken(refreshToken) {
  const response = await fetch("https://v1.0account.com/oauth/token", {
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
