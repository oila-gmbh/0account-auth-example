# OIDC Flow — Go (coreos/go-oidc)

Standard Go OIDC library with full control over every step. Handles login,
callback, server-to-server logout, and automatic token refresh.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/auth/login` | Start OIDC login (redirect to 0account) |
| `GET` | `/auth/callback` | Handle OIDC callback, verify id_token, create session |
| `GET` | `/auth/logout` | Clear session + server-to-server logout |

## Setup

```bash
cp .env.example .env
# Edit .env with your credentials

go mod tidy
go run main.go
# Server starts on :8080
```

Register `http://localhost:8080/auth/callback` as a redirect URI in your 0account app dashboard.

## Usage in handlers

```go
// In any protected handler, get and auto-refresh the session:
sess, err := getSession(r)
if err != nil {
    http.Redirect(w, r, "/auth/login", http.StatusFound)
    return
}
// sess.UserID, sess.Email, sess.Name, sess.AccessToken
```

## Environment variables

| Variable | Description |
|---|---|
| `CLIENT_ID` | Your OAuth client ID |
| `CLIENT_SECRET` | Your OAuth client secret |
