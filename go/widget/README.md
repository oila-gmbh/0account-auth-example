# Widget Flow — Go (Fiber)

Backend for the `<zero-account>` widget. The widget handles PKCE, QR code, and the SSE session.
Your backend only needs one endpoint.

## How it works

1. User clicks the widget button → `<zero-account>` calls `POST /oauth/request` on 0account, shows QR code
2. User scans with the 0account mobile app and approves
3. Widget POSTs `{ code, code_verifier, state, nonce, redirect_uri }` to your `finalize-uri`
4. Your backend exchanges the code for tokens at `POST /oauth/token`

## Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/finalize` | Exchange code for tokens, create session |
| `GET` | `/auth/logout` | Clear session + server-to-server 0account logout |
| `POST` | `/auth/refresh` | Refresh the access token |

## Setup

```bash
cp .env.example .env
# Edit .env with your credentials

go mod tidy
go run main.go
# Server starts on :8080
```

## Frontend snippet

```html
<script type="module" src="https://unpkg.com/@0account/web/dist/0account-web.js"></script>

<zero-account
  app-id="YOUR_CLIENT_ID"
  redirect-uri="http://localhost:3000/auth/callback"
  finalize-uri="http://localhost:8080/auth/finalize"
  scope="openid profile email offline_access"
  with-button
></zero-account>
```

## Environment variables

| Variable | Description |
|---|---|
| `CLIENT_ID` | Your OAuth client ID |
| `CLIENT_SECRET` | Your OAuth client secret |
