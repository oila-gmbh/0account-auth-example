package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/openidConnect"
)

const (
	authorizationURL = "https://v1.0account.com/oauth/authorize"
	tokenURL         = "https://v1.0account.com/oauth/token"
	logoutURL        = "https://v1.0account.com/oauth/logout"
)

// appStore holds the application session (user info + tokens).
// In production, use a persistent session store (e.g. Redis).
var appStore *sessions.CookieStore

// oidcStore holds the transient OIDC handshake values (state, nonce, verifier).
var oidcStore *sessions.CookieStore

func randomBase64URL(n int) string {
	b := make([]byte, n)
	rand.Read(b) //nolint:errcheck
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateCodeVerifier creates a PKCE code_verifier (RFC 7636 §4.1).
func generateCodeVerifier() string { return randomBase64URL(32) }

// generateCodeChallenge computes code_challenge = BASE64URL(SHA256(verifier)).
func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func redirectURI() string {
	if v := os.Getenv("REDIRECT_URI"); v != "" {
		return v
	}
	return "http://localhost:8080/auth/callback"
}

func main() {
	sessionSecret := os.Getenv("SESSION_SECRET")
	appStore = sessions.NewCookieStore([]byte(sessionSecret))
	oidcStore = sessions.NewCookieStore([]byte(sessionSecret))

	// Use Goth's openidConnect provider for discovery validation and user fetching.
	// Auth URL building uses manual PKCE (code_challenge/code_verifier), and token
	// exchange uses http.PostForm to guarantee client_secret_post auth method.
	// After token exchange, FetchUser populates the standard goth.User struct.
	provider, err := openidConnect.New(
		os.Getenv("CLIENT_ID"),
		os.Getenv("CLIENT_SECRET"),
		redirectURI(),
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
	http.ListenAndServe(":8080", nil) //nolint:errcheck
}

// GET /auth/login?provider=openidConnect
func handleLogin(w http.ResponseWriter, r *http.Request) {
	state := randomBase64URL(16)
	nonce := randomBase64URL(16)
	verifier := generateCodeVerifier()

	// Persist state, nonce, and PKCE verifier for callback validation.
	sess, _ := oidcStore.Get(r, "oidc")
	sess.Values["state"] = state
	sess.Values["nonce"] = nonce
	sess.Values["verifier"] = verifier
	sess.Save(r, w) //nolint:errcheck

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {os.Getenv("CLIENT_ID")},
		"redirect_uri":          {redirectURI()},
		"scope":                 {"openid profile email offline_access"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {generateCodeChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, authorizationURL+"?"+params.Encode(), http.StatusFound)
}

// GET /auth/callback
func handleCallback(w http.ResponseWriter, r *http.Request) {
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		http.Error(w, "auth error: "+errParam+": "+r.URL.Query().Get("error_description"), http.StatusUnauthorized)
		return
	}

	sess, _ := oidcStore.Get(r, "oidc")
	state, _ := sess.Values["state"].(string)
	nonce, _ := sess.Values["nonce"].(string)
	verifier, _ := sess.Values["verifier"].(string)

	if r.URL.Query().Get("state") != state || state == "" {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	// Exchange authorization code for tokens using client_secret_post + PKCE verifier.
	tokenResp, err := http.PostForm(tokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {r.URL.Query().Get("code")},
		"redirect_uri":  {redirectURI()},
		"client_id":     {os.Getenv("CLIENT_ID")},
		"client_secret": {os.Getenv("CLIENT_SECRET")},
		"code_verifier": {verifier},
	})
	if err != nil {
		http.Error(w, "token exchange: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer tokenResp.Body.Close()

	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokens); err != nil || tokens.AccessToken == "" {
		http.Error(w, "failed to parse token response", http.StatusInternalServerError)
		return
	}

	// Validate nonce from the ID token payload (signature verification omitted for brevity).
	if nonce != "" && tokens.IDToken != "" {
		if claims := parseIDToken(tokens.IDToken); claims["nonce"] != nonce {
			http.Error(w, "nonce mismatch", http.StatusBadRequest)
			return
		}
	}

	// Use Goth's FetchUser to fetch and map the userinfo claims to a goth.User struct.
	gothSess := &openidConnect.Session{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		IDToken:      tokens.IDToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second),
	}
	provider, err := goth.GetProvider("openid-connect")
	if err != nil {
		http.Error(w, "get provider: "+err.Error(), http.StatusInternalServerError)
		return
	}
	user, err := provider.FetchUser(gothSess)
	if err != nil {
		http.Error(w, "fetch user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// user.UserID, user.Email, user.Name, user.FirstName, user.LastName
	// user.AccessToken, user.RefreshToken, user.IDToken
	// TODO: upsert user into your database by user.UserID

	appSess, _ := appStore.Get(r, "app")
	appSess.Values["user_id"] = user.UserID
	appSess.Values["email"] = user.Email
	appSess.Values["id_token"] = user.IDToken
	appSess.Values["access_token"] = user.AccessToken
	appSess.Values["refresh_token"] = user.RefreshToken
	appSess.Save(r, w) //nolint:errcheck

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, _ := appStore.Get(r, "app")
	idToken, _ := sess.Values["id_token"].(string)

	sess.Options.MaxAge = -1
	sess.Save(r, w) //nolint:errcheck

	if idToken != "" {
		http.PostForm(logoutURL, url.Values{"id_token_hint": {idToken}}) //nolint:errcheck
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

	provider, err := goth.GetProvider("openid-connect")
	if err != nil {
		return err
	}
	resp, err := provider.(*openidConnect.Provider).RefreshTokenWithIDToken(refreshToken)
	if err != nil {
		return err
	}

	sess.Values["access_token"] = resp.AccessToken
	if resp.RefreshToken != "" {
		sess.Values["refresh_token"] = resp.RefreshToken
	}
	if resp.IdToken != "" {
		sess.Values["id_token"] = resp.IdToken
	}
	return sess.Save(r, w)
}

// parseIDToken decodes an ID token's payload without verifying the signature.
// In production, verify the signature using the provider's JWKS endpoint.
func parseIDToken(idToken string) map[string]interface{} {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]interface{}
	json.Unmarshal(payload, &claims) //nolint:errcheck
	return claims
}


