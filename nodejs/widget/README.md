# Widget Flow — Node.js / Express

Backend for the `<zero-account>` widget. One endpoint to exchange the auth code for tokens.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/finalize` | Exchange code for tokens, create session |
| `GET` | `/auth/logout` | Clear session + server-to-server logout |
| `POST` | `/auth/refresh` | Refresh the access token |

## Setup

```bash
cp .env.example .env
# Edit .env with your credentials

npm install
npm run dev
# Server starts on http://localhost:3000
```

## Frontend snippet

```html
<script type="module" src="https://unpkg.com/@0account/web/dist/0account-web.js"></script>

<zero-account
  app-id="YOUR_CLIENT_ID"
  redirect-uri="http://localhost:3000/auth/callback"
  finalize-uri="http://localhost:3000/auth/finalize"
  scope="openid profile email offline_access"
  with-button
></zero-account>
```

## Environment variables

| Variable | Description |
|---|---|
| `CLIENT_ID` | Your OAuth client ID |
| `CLIENT_SECRET` | Your OAuth client secret |
| `SESSION_SECRET` | Random secret for session signing |
