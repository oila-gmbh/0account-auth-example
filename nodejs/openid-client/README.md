# OIDC Flow — Node.js / Express + openid-client

Certified OIDC implementation with full control. Handles login (PKCE), callback,
server-to-server logout, and automatic token refresh.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/auth/login` | Start OIDC login (redirect to 0account) |
| `GET` | `/auth/callback` | Handle OIDC callback, create session |
| `GET` | `/auth/logout` | Clear session + server-to-server logout |
| `GET` | `/dashboard` | Protected route example |

## Setup

```bash
cp .env.example .env
# Edit .env with your credentials

npm install
npm run dev
# Server starts on http://localhost:3000
```

Register `http://localhost:3000/auth/callback` as a redirect URI in your 0account app dashboard.

## Environment variables

| Variable | Description |
|---|---|
| `CLIENT_ID` | Your OAuth client ID |
| `CLIENT_SECRET` | Your OAuth client secret |
| `SESSION_SECRET` | Random secret for session signing |
