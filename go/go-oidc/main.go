package main

import (
	"context"
	"crypto/rand"
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

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Session stores the authenticated user's tokens.
// Replace the in-memory map with a distributed store (e.g. Redis) in production.
type Session struct {
	UserID       string
	Email        string
	Name         string
	IDToken      string
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}

var (
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
	secureCookies bool
	mu           sync.RWMutex
	sessions     = map[string]*Session{}
)

func init() {
	provider, err := oidc.NewProvider(context.Background(), "https://v1.0account.com")
	if err != nil {
		panic(err)
	}
	redirectURI := os.Getenv("REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = "http://localhost:8080/auth/callback"
	}
	secureCookies = strings.HasPrefix(redirectURI, "https://")
	oauth2Config = &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  redirectURI,
		Endpoint:     provider.Endpoint(),
		// offline_access requests a refresh token
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", "offline_access"},
	}
	verifier = provider.Verifier(&oidc.Config{ClientID: os.Getenv("CLIENT_ID")})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	state := randomToken()
	pkceVerifier := oauth2.GenerateVerifier()
	http.SetCookie(w, secureCookie("state", state, 300))
	http.SetCookie(w, secureCookie("pkce", pkceVerifier, 300))
	http.Redirect(w, r,
		oauth2Config.AuthCodeURL(state, oauth2.S256ChallengeOption(pkceVerifier)),
		http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie("state")
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		log.Printf("[go-oidc] invalid state: cookie_err=%v url_state=%q cookie_state=%q", err, r.URL.Query().Get("state"), stateCookie.Value)
		http.Error(w, "invalid state", http.StatusForbidden)
		return
	}
	pkceCookie, err := r.Cookie("pkce")
	if err != nil {
		log.Printf("[go-oidc] missing pkce cookie: %v", err)
		http.Error(w, "missing pkce verifier", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "state", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "pkce", MaxAge: -1})

	token, err := oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"),
		oauth2.VerifierOption(pkceCookie.Value))
	if err != nil {
		log.Printf("[go-oidc] token exchange failed: %v", err)
		http.Error(w, "token exchange failed", http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Printf("[go-oidc] missing id_token in token response")
		http.Error(w, "missing id_token", http.StatusUnauthorized)
		return
	}
	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		log.Printf("[go-oidc] id_token verification failed: %v", err)
		http.Error(w, "invalid id_token", http.StatusUnauthorized)
		return
	}

	var claims struct {
		Sub        string `json:"sub"`
		Email      string `json:"email"`
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
	}
	idToken.Claims(&claims)

	// TODO: upsert user into your database by claims.Sub
	log.Printf("[go-oidc] authenticated: sub=%s email=%s token_expiry=%v refresh_token_set=%v",
		claims.Sub, claims.Email, token.Expiry, token.RefreshToken != "")

	sessID := randomToken()
	mu.Lock()
	sessions[sessID] = &Session{
		UserID:       claims.Sub,
		Email:        claims.Email,
		Name:         fmt.Sprintf("%s %s", claims.GivenName, claims.FamilyName),
		IDToken:      rawIDToken,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}
	mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessID,
		HttpOnly: true,
		Secure:   secureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 30,
		Path:     "/",
	})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session")
	http.SetCookie(w, &http.Cookie{Name: "session", MaxAge: -1, Path: "/"})

	var idToken string
	if cookie != nil {
		mu.Lock()
		if sess, ok := sessions[cookie.Value]; ok {
			idToken = sess.IDToken
			delete(sessions, cookie.Value)
		}
		mu.Unlock()
	}

	if idToken != "" {
		// Server-to-server: terminate the session on 0account's side without a browser redirect.
		http.PostForm("https://v1.0account.com/oauth/logout", url.Values{ //nolint:errcheck
			"id_token_hint": {idToken},
		})
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// getSession returns the current session, refreshing the access token
// automatically when it is within 5 minutes of expiry.
func getSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie("session")
	if err != nil {
		log.Printf("[go-oidc] getSession: no session cookie: %v", err)
		return nil, fmt.Errorf("not authenticated")
	}
	mu.RLock()
	sess := sessions[cookie.Value]
	mu.RUnlock()
	if sess == nil {
		log.Printf("[go-oidc] getSession: session not found for cookie value")
		return nil, fmt.Errorf("session not found")
	}
	// Only proactively refresh when we have a known expiry that is close.
	// If Expiry is zero (server omitted expires_in), skip refresh — the token
	// is assumed valid until an API call explicitly returns 401.
	if !sess.Expiry.IsZero() && time.Until(sess.Expiry) < 5*time.Minute {
		log.Printf("[go-oidc] getSession: token near expiry (%v), refreshing", sess.Expiry)
		if err := refreshSession(r.Context(), sess); err != nil {
			log.Printf("[go-oidc] getSession: refresh failed: %v", err)
			return nil, fmt.Errorf("token refresh failed: %w", err)
		}
	}
	return sess, nil
}

func refreshSession(ctx context.Context, sess *Session) error {
	if sess.RefreshToken == "" {
		return fmt.Errorf("no refresh token stored")
	}
	src := oauth2Config.TokenSource(ctx, &oauth2.Token{RefreshToken: sess.RefreshToken})
	newToken, err := src.Token()
	if err != nil {
		return err
	}
	mu.Lock()
	sess.AccessToken = newToken.AccessToken
	sess.Expiry = newToken.Expiry
	if newToken.RefreshToken != "" {
		sess.RefreshToken = newToken.RefreshToken // accept rotated refresh token
	}
	mu.Unlock()
	return nil
}

func secureCookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		Secure:   secureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

func randomToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	sess, err := getSession(r)
	if err != nil {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"userId": sess.UserID,
		"email":  sess.Email,
	})
}

func main() {
	http.HandleFunc("GET /auth/login", handleLogin)
	http.HandleFunc("GET /auth/callback", handleCallback)
	http.HandleFunc("GET /auth/logout", handleLogout)
	http.HandleFunc("GET /dashboard", handleDashboard)
	http.ListenAndServe(":8080", nil)
}
