package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

// Token store — replace with Redis in production.
var (
	mu       sync.RWMutex
	tokenMap = map[string]TokenData{} // sessID → tokens
)

type TokenData struct {
	UserID       string
	Email        string
	Name         string
	AccessToken  string
	RefreshToken string
	IDToken      string
	Expiry       time.Time
}

type FinalizeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type UserInfoResponse struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

var store *session.Store

// revokedSubs tracks subjects whose sessions were revoked via back-channel logout.
// Cookie-based sessions cannot be directly invalidated, so we check this on each request.
// In production, use a shared store (e.g. Redis) across all server instances.
var revokedSubs sync.Map

var (
	jwksOnce     sync.Once
	logoutPubKey ed25519.PublicKey
	appOrigin    = getEnv("APP_ORIGIN", "http://localhost:3000")
	selfURL      = getEnv("SELF_URL", "http://localhost:8085")
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

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
			log.Printf("[widget] getLogoutKey: JWKS fetch failed: %v", err)
			return
		}
		defer resp.Body.Close()
		var set struct {
			Keys []jwkItem `json:"keys"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
			log.Printf("[widget] getLogoutKey: JWKS decode failed: %v", err)
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
		log.Printf("[widget] getLogoutKey: no Ed25519 key found in JWKS")
	})
	return logoutPubKey
}

// parseLogoutToken verifies the EdDSA signature of a back-channel logout JWT and returns sub.
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

var loginHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in — widget</title>
<script src="https://unpkg.com/@0account/web@1.3.4/dist/0account-web.umd.cjs"></script>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#09090b;color:#fafafa;min-height:100vh;display:flex;align-items:center;justify-content:center}</style>
</head><body>
<zero-account app-id="%s" redirect-uri="%s" finalize-uri="/auth/finalize" scope="openid profile email offline_access" with-button></zero-account>
<script>
  document.querySelector('zero-account').addEventListener('0account-authenticated', function() {
    window.location.href = '%s'
  })
</script>
</body></html>`

var dashboardHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard — widget</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#09090b;color:#fafafa;min-height:100vh;display:flex;align-items:center;justify-content:center}.card{background:#18181b;border:1px solid #27272a;border-radius:16px;padding:32px;width:360px}h1{font-size:1.125rem;font-weight:600;margin-bottom:20px}.row{display:flex;justify-content:space-between;gap:12px;background:#27272a66;border-radius:8px;padding:8px 12px;margin-bottom:8px}.label{font-size:.75rem;color:#a1a1aa;white-space:nowrap}.value{font-family:'SF Mono',monospace;font-size:.75rem;color:#e4e4e7;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px}.btn{display:block;margin-top:20px;padding:10px 16px;border:1px solid #3f3f46;background:transparent;color:#a1a1aa;border-radius:10px;font-size:.875rem;text-align:center;text-decoration:none;transition:background .15s}.btn:hover{background:#27272a;color:#e4e4e7}</style>
</head><body><div class="card">
<h1>Dashboard</h1>
<div class="row"><span class="label">User ID</span><span class="value">%s</span></div>
<div class="row"><span class="label">Email</span><span class="value">%s</span></div>
<div class="row"><span class="label">Name</span><span class="value">%s</span></div>
<a href="/auth/logout" class="btn">Sign out</a>
</div>
<script>(function(){var t=setInterval(async function(){try{var r=await fetch('/auth/status');if(r.status===401){clearInterval(t);window.location.href='/';}}catch(e){}},3000);})();</script>
</body></html>`

// GET / — show login page; redirect to central profile if already authenticated
func handleHome(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err == nil {
		if uid, _ := sess.Get("user_id").(string); uid != "" {
			if _, revoked := revokedSubs.Load(uid); !revoked {
				profileURL := appOrigin + "/profile?url=" + url.QueryEscape(selfURL)
				return c.Redirect(profileURL, fiber.StatusFound)
			}
		}
	}
	clientID := html.EscapeString(os.Getenv("CLIENT_ID"))
	redirectURI := html.EscapeString(os.Getenv("REDIRECT_URI"))
	if redirectURI == "" {
		redirectURI = "http://localhost:8080/"
	}
	profileURL := appOrigin + "/profile?url=" + url.QueryEscape(selfURL)
	c.Type("html")
	return c.SendString(fmt.Sprintf(loginHTML, clientID, redirectURI, profileURL))
}

// GET /dashboard — redirect to central profile (backward compat)
func handleDashboard(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err != nil {
		return c.Redirect("/", fiber.StatusFound)
	}
	userID, _ := sess.Get("user_id").(string)
	if userID == "" {
		return c.Redirect("/", fiber.StatusFound)
	}
	if _, revoked := revokedSubs.Load(userID); revoked {
		sess.Destroy()
		return c.Redirect("/", fiber.StatusFound)
	}
	return c.Redirect(appOrigin+"/profile?url="+url.QueryEscape(selfURL), fiber.StatusFound)
}

// GET /auth/me — session info + integration metadata for the central profile page
func handleMe(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "not authenticated"})
	}
	userID, _ := sess.Get("user_id").(string)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "not authenticated"})
	}
	if _, revoked := revokedSubs.Load(userID); revoked {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "revoked"})
	}
	email, _ := sess.Get("email").(string)
	name, _ := sess.Get("name").(string)
	return c.JSON(fiber.Map{
		"userId": userID,
		"email":  email,
		"name":   name,
		"integration": fiber.Map{
			"name":     "Widget",
			"language": "Go",
			"flow":     "widget",
			"library":  "@0account/web",
			"url":      selfURL,
		},
	})
}

// POST /auth/finalize — called by the widget after the user approves
func handleFinalize(c *fiber.Ctx) error {
	var req FinalizeRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if req.Code == "" || req.CodeVerifier == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing code or code_verifier"})
	}

	resp, err := http.PostForm("https://v1.0account.com/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {req.Code},
		"code_verifier": {req.CodeVerifier},
		"redirect_uri":  {req.RedirectURI},
		"client_id":     {os.Getenv("CLIENT_ID")},
		"client_secret": {os.Getenv("CLIENT_SECRET")},
	})
	if err != nil || resp.StatusCode != http.StatusOK {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "token exchange failed"})
	}
	defer resp.Body.Close()

	var tokens TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to parse tokens"})
	}

	// Fetch user info to get the subject (user ID)
	userInfo, err := fetchUserInfo(tokens.AccessToken)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch user info"})
	}
	// TODO: upsert user into your database by userInfo.Sub

	sess, err := store.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "session error"})
	}
	sess.Set("user_id", userInfo.Sub)
	sess.Set("email", userInfo.Email)
	sess.Set("name", userInfo.Name)
	sess.Set("id_token", tokens.IDToken)
	sess.Set("access_token", tokens.AccessToken)
	sess.Set("refresh_token", tokens.RefreshToken)
	sess.Set("expiry", time.Now().Add(time.Duration(tokens.ExpiresIn)*time.Second).Unix())
	if err := sess.Save(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to save session"})
	}

	// Clear any previously revoked entry for this subject on fresh login.
	revokedSubs.Delete(userInfo.Sub)

	return c.JSON(fiber.Map{"success": true})
}

// GET /auth/logout
func handleLogout(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err != nil {
		return c.Redirect("/", fiber.StatusFound)
	}

	idToken, _ := sess.Get("id_token").(string)
	returnTo := c.Query("return_to")
	if returnTo == "" || !strings.HasPrefix(returnTo, appOrigin) {
		returnTo = "/"
	}
	sess.Destroy()

	if idToken != "" {
		http.PostForm("https://v1.0account.com/oauth/logout", url.Values{ //nolint:errcheck
			"id_token_hint": {idToken},
		})
	}
	return c.Redirect(returnTo, fiber.StatusFound)
}

// POST /auth/backchannel-logout — called by 0account when the user logs out remotely.
// Register this URI as backchannel_logout_uri in your 0account app settings.
func handleBackchannelLogout(c *fiber.Ctx) error {
	rawToken := c.FormValue("logout_token")
	sub, err := parseLogoutToken(rawToken)
	if err != nil {
		log.Printf("[widget] backchannel-logout: invalid token: %v", err)
		return c.SendStatus(fiber.StatusBadRequest)
	}
	revokedSubs.Store(sub, struct{}{})
	log.Printf("[widget] backchannel-logout: revoked sub=%s", sub)
	return c.SendStatus(fiber.StatusOK)
}

// POST /auth/refresh
func handleRefresh(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "not authenticated"})
	}
	refreshToken, _ := sess.Get("refresh_token").(string)
	if refreshToken == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "no refresh token"})
	}

	resp, err := http.PostForm("https://v1.0account.com/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {os.Getenv("CLIENT_ID")},
		"client_secret": {os.Getenv("CLIENT_SECRET")},
	})
	if err != nil || resp.StatusCode != http.StatusOK {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "refresh failed"})
	}
	defer resp.Body.Close()

	var tokens TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to parse tokens"})
	}

	sess.Set("access_token", tokens.AccessToken)
	sess.Set("expiry", time.Now().Add(time.Duration(tokens.ExpiresIn)*time.Second).Unix())
	if tokens.RefreshToken != "" {
		sess.Set("refresh_token", tokens.RefreshToken) // accept rotated refresh token
	}
	if err := sess.Save(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to save session"})
	}

	return c.JSON(fiber.Map{"success": true})
}

func fetchUserInfo(accessToken string) (*UserInfoResponse, error) {
	req, _ := http.NewRequest("GET", "https://v1.0account.com/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var info UserInfoResponse
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func main() {
	store = session.New(session.Config{
		Expiration:     30 * 24 * time.Hour,
		CookieHTTPOnly: true,
		CookieSecure:   os.Getenv("SECURE_COOKIES") == "true",
		CookieSameSite: "Lax",
	})

	app := fiber.New()

	// CORS: allow the showcase origin to make credentialed fetch requests.
	app.Use(func(c *fiber.Ctx) error {
		if c.Get("Origin") == appOrigin {
			c.Set("Access-Control-Allow-Origin", appOrigin)
			c.Set("Access-Control-Allow-Credentials", "true")
			c.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			c.Set("Access-Control-Allow-Headers", "Content-Type")
		}
		if c.Method() == fiber.MethodOptions {
			return c.SendStatus(fiber.StatusNoContent)
		}
		return c.Next()
	})

	app.Get("/", handleHome)
	app.Get("/dashboard", handleDashboard)
	app.Get("/auth/me", handleMe)
	app.Get("/auth/status", func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"})
		}
		userID, _ := sess.Get("user_id").(string)
		if userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"})
		}
		if _, revoked := revokedSubs.Load(userID); revoked {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "revoked"})
		}
		return c.JSON(fiber.Map{"ok": true})
	})
	app.Post("/auth/finalize", handleFinalize)
	app.Get("/auth/logout", handleLogout)
	app.Post("/auth/backchannel-logout", handleBackchannelLogout)
	app.Post("/auth/refresh", handleRefresh)
	app.Listen(":8080")
}
