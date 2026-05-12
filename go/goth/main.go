package main

import (
	"net/http"
	"net/url"
	"os"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/openidConnect"
)

// appStore holds the application session (user info + tokens).
// In production, use a persistent session store (e.g. Redis).
var appStore *sessions.CookieStore

func main() {
	sessionSecret := os.Getenv("SESSION_SECRET")
	appStore = sessions.NewCookieStore([]byte(sessionSecret))
	gothic.Store = sessions.NewCookieStore([]byte(sessionSecret))

	redirectURI := os.Getenv("REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = "http://localhost:8080/auth/callback"
	}
	provider, err := openidConnect.New(
		os.Getenv("CLIENT_ID"),
		os.Getenv("CLIENT_SECRET"),
		redirectURI,
		// Goth expects the full discovery document URL, not just the issuer.
		"https://v1.0account.com/.well-known/openid-configuration",
		"openid", "profile", "email", "offline_access",
	)
	if err != nil {
		panic("goth openidConnect.New: " + err.Error())
	}
	goth.UseProviders(provider)

	http.HandleFunc("GET /auth/login", handleLogin)
	http.HandleFunc("GET /auth/callback", handleCallback)
	http.HandleFunc("GET /auth/logout", handleLogout)
	http.ListenAndServe(":8080", nil)
}

// GET /auth/login?provider=openidConnect
func handleLogin(w http.ResponseWriter, r *http.Request) {
	gothic.BeginAuthHandler(w, r)
}

// GET /auth/callback?provider=openidConnect
func handleCallback(w http.ResponseWriter, r *http.Request) {
	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// user.UserID, user.Email, user.Name, user.AvatarURL
	// user.AccessToken, user.RefreshToken, user.IDToken, user.ExpiresAt
	// TODO: upsert user into your database by user.UserID

	sess, _ := appStore.Get(r, "app")
	sess.Values["user_id"] = user.UserID
	sess.Values["email"] = user.Email
	sess.Values["id_token"] = user.IDToken
	sess.Values["access_token"] = user.AccessToken
	sess.Values["refresh_token"] = user.RefreshToken
	sess.Save(r, w)

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, _ := appStore.Get(r, "app")
	idToken, _ := sess.Values["id_token"].(string)

	// Clear application session
	sess.Options.MaxAge = -1
	sess.Save(r, w)
	gothic.Logout(w, r)

	if idToken != "" {
		// Server-to-server: terminate the session on 0account's side without a browser redirect.
		http.PostForm("https://v1.0account.com/oauth/logout", url.Values{ //nolint:errcheck
			"id_token_hint": {idToken},
		})
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// refreshTokens refreshes the access token using the stored refresh token.
// Call this when user.ExpiresAt is in the past before making API requests.
func refreshTokens(w http.ResponseWriter, r *http.Request) error {
	sess, _ := appStore.Get(r, "app")
	refreshToken, _ := sess.Values["refresh_token"].(string)
	if refreshToken == "" {
		return http.ErrNoCookie
	}

	provider, err := goth.GetProvider("openidConnect")
	if err != nil {
		return err
	}
	newToken, err := provider.RefreshToken(refreshToken)
	if err != nil {
		return err
	}

	sess.Values["access_token"] = newToken.AccessToken
	if newToken.RefreshToken != "" {
		sess.Values["refresh_token"] = newToken.RefreshToken // accept rotated refresh token
	}
	return sess.Save(r, w)
}


