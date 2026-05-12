package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
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
	sess.Set("id_token", tokens.IDToken)
	sess.Set("access_token", tokens.AccessToken)
	sess.Set("refresh_token", tokens.RefreshToken)
	sess.Set("expiry", time.Now().Add(time.Duration(tokens.ExpiresIn)*time.Second).Unix())
	if err := sess.Save(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to save session"})
	}

	return c.JSON(fiber.Map{"success": true})
}

// GET /auth/logout
func handleLogout(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err != nil {
		return c.Redirect("/", fiber.StatusFound)
	}

	idToken, _ := sess.Get("id_token").(string)
	sess.Destroy()

	if idToken != "" {
		// Server-to-server: terminate the session on 0account's side without a browser redirect.
		http.PostForm("https://v1.0account.com/oauth/logout", url.Values{ //nolint:errcheck
			"id_token_hint": {idToken},
		})
	}
	return c.Redirect("/", fiber.StatusFound)
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
		CookieSecure:   true,
		CookieSameSite: "Lax",
	})

	app := fiber.New()
	app.Post("/auth/finalize", handleFinalize)
	app.Get("/auth/logout", handleLogout)
	app.Post("/auth/refresh", handleRefresh)
	app.Listen(":8080")
}
