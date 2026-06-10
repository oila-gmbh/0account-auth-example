package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
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

// revokedSubs tracks subjects whose sessions were revoked via back-channel logout.
// Cookie-based sessions cannot be directly invalidated, so we check this on each request.
// In production, use a shared store (e.g. Redis) across all server instances.
var revokedSubs sync.Map

var (
	jwksOnce     sync.Once
	logoutPubKey ed25519.PublicKey
	appOrigin    = getEnv("APP_ORIGIN", "http://localhost:3000")
	selfURL      = getEnv("SELF_URL", "http://localhost:8084")
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// jwkItem is the minimal JWKS representation needed to extract an Ed25519 key.
type jwkItem struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// getLogoutKey fetches the issuer's Ed25519 public key from JWKS (cached).
func getLogoutKey() ed25519.PublicKey {
	jwksOnce.Do(func() {
		resp, err := http.Get("https://v1.0account.com/.well-known/jwks.json")
		if err != nil {
			log.Printf("[goth] getLogoutKey: JWKS fetch failed: %v", err)
			return
		}
		defer resp.Body.Close()
		var set struct {
			Keys []jwkItem `json:"keys"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
			log.Printf("[goth] getLogoutKey: JWKS decode failed: %v", err)
			return
		}
		for _, k := range set.Keys {
			if k.Kty == "OKP" && k.Crv == "Ed25519" {
				raw, err := base64.RawURLEncoding.DecodeString(k.X)
				if err == nil && len(raw) == ed25519.PublicKeySize {
					logoutPubKey = ed25519.PublicKey(raw)
					return
				}
			}
		}
		log.Printf("[goth] getLogoutKey: no Ed25519 key found in JWKS")
	})
	return logoutPubKey
}

// parseLogoutToken verifies the EdDSA signature of a back-channel logout JWT
// and returns the sub claim.
func parseLogoutToken(rawToken string) (string, error) {
	parts := strings.SplitN(rawToken, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed JWT")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("invalid signature encoding")
	}
	key := getLogoutKey()
	if key == nil {
		return "", fmt.Errorf("logout key unavailable")
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return "", fmt.Errorf("invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid payload encoding")
	}
	var claims struct {
		Sub    string         `json:"sub"`
		Events map[string]any `json:"events"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Sub == "" {
		return "", fmt.Errorf("invalid claims")
	}
	if _, ok := claims.Events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		return "", fmt.Errorf("missing backchannel-logout event")
	}
	return claims.Sub, nil
}

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

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard — goth</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#09090b;color:#fafafa;min-height:100vh;display:flex;align-items:center;justify-content:center}.card{background:#18181b;border:1px solid #27272a;border-radius:16px;padding:32px;width:360px}h1{font-size:1.125rem;font-weight:600;margin-bottom:20px}.row{display:flex;justify-content:space-between;gap:12px;background:#27272a66;border-radius:8px;padding:8px 12px;margin-bottom:8px}.label{font-size:.75rem;color:#a1a1aa;white-space:nowrap}.value{font-family:'SF Mono',monospace;font-size:.75rem;color:#e4e4e7;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px}.btn{display:block;margin-top:20px;padding:10px 16px;border:1px solid #3f3f46;background:transparent;color:#a1a1aa;border-radius:10px;font-size:.875rem;text-align:center;text-decoration:none;transition:background .15s}.btn:hover{background:#27272a;color:#e4e4e7}</style>
</head><body><div class="card">
<h1>Dashboard</h1>
<div class="row"><span class="label">User ID</span><span class="value">%s</span></div>
<div class="row"><span class="label">Email</span><span class="value">%s</span></div>
<div class="row"><span class="label">Name</span><span class="value">%s</span></div>
<a href="/auth/logout" class="btn">Sign out</a>
</div>
<script>(function(){var t=setInterval(async function(){try{var r=await fetch('/auth/status');if(r.status===401){clearInterval(t);window.location.href='/auth/login';}}catch(e){}},3000);})();</script>
</body></html>`

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	sess, _ := appStore.Get(r, "app")
	userID, _ := sess.Values["user_id"].(string)
	if userID == "" {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	if _, revoked := revokedSubs.Load(userID); revoked {
		sess.Options.MaxAge = -1
		sess.Save(r, w) //nolint:errcheck
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	http.Redirect(w, r, appOrigin+"/profile?url="+url.QueryEscape(selfURL), http.StatusFound)
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	sess, _ := appStore.Get(r, "app")
	userID, _ := sess.Values["user_id"].(string)
	if userID == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"not authenticated"}`)) //nolint:errcheck
		return
	}
	if _, revoked := revokedSubs.Load(userID); revoked {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"revoked"}`)) //nolint:errcheck
		return
	}
	email, _ := sess.Values["email"].(string)
	name, _ := sess.Values["name"].(string)
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"userId": userID,
		"email":  email,
		"name":   name,
		"integration": map[string]string{
			"name":     "Goth",
			"language": "Go",
			"flow":     "oidc",
			"library":  "markbates/goth",
			"url":      selfURL,
		},
	})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	sess, _ := appStore.Get(r, "app")
	userID, _ := sess.Values["user_id"].(string)
	if userID == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthenticated"}`)) //nolint:errcheck
		return
	}
	if _, revoked := revokedSubs.Load(userID); revoked {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"revoked"}`)) //nolint:errcheck
		return
	}
	w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
}

// handleBackchannelLogout processes a back-channel logout token from 0account,
// marking the subject as revoked so future protected requests are rejected.
func handleBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	rawToken := r.FormValue("logout_token")
	if rawToken == "" {
		http.Error(w, "missing logout_token", http.StatusBadRequest)
		return
	}
	sub, err := parseLogoutToken(rawToken)
	if err != nil {
		log.Printf("[goth] backchannel-logout: invalid token: %v", err)
		http.Error(w, "invalid logout_token", http.StatusBadRequest)
		return
	}
	revokedSubs.Store(sub, struct{}{})
	log.Printf("[goth] backchannel-logout: revoked sub=%s", sub)
	w.WriteHeader(http.StatusOK)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin == appOrigin {
			w.Header().Set("Access-Control-Allow-Origin", appOrigin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
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

	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", handleLogin)
	mux.HandleFunc("GET /auth/callback", handleCallback)
	mux.HandleFunc("GET /auth/logout", handleLogout)
	mux.HandleFunc("GET /auth/status", handleStatus)
	mux.HandleFunc("GET /auth/me", handleMe)
	mux.HandleFunc("GET /dashboard", handleDashboard)
	mux.HandleFunc("POST /auth/backchannel-logout", handleBackchannelLogout)
	http.ListenAndServe(":8080", corsMiddleware(mux)) //nolint:errcheck
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
	appSess.Values["name"] = user.Name
	appSess.Values["id_token"] = user.IDToken
	appSess.Values["access_token"] = user.AccessToken
	appSess.Values["refresh_token"] = user.RefreshToken
	appSess.Save(r, w) //nolint:errcheck

	// Clear any previously revoked entry for this subject on fresh login.
	revokedSubs.Delete(user.UserID)

	http.Redirect(w, r, appOrigin+"/profile?url="+url.QueryEscape(selfURL), http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, _ := appStore.Get(r, "app")
	idToken, _ := sess.Values["id_token"].(string)

	sess.Options.MaxAge = -1
	sess.Save(r, w) //nolint:errcheck

	if idToken != "" {
		http.PostForm(logoutURL, url.Values{"id_token_hint": {idToken}}) //nolint:errcheck
	}
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" || !strings.HasPrefix(returnTo, appOrigin) {
		returnTo = "/auth/login"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
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


