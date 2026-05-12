# OIDC Flow — Go (goth)

The simplest Go OIDC integration. [goth](https://github.com/markbates/goth) wraps provider discovery,
state, PKCE, and token exchange into two route handlers.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/auth/login?provider=openidConnect` | Start OIDC login (redirect to 0account) |
| `GET` | `/auth/callback?provider=openidConnect` | Handle OIDC callback, create session |
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

## Environment variables

| Variable | Description |
|---|---|
| `CLIENT_ID` | Your OAuth client ID |
| `CLIENT_SECRET` | Your OAuth client secret |
| `SESSION_SECRET` | Random secret for cookie signing |
