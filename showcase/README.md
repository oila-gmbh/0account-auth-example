# Showcase — 0account Auth Example

A Next.js App Router app demonstrating both 0account authentication flows side by side.

## What's inside

| Route | Description |
|---|---|
| `/` | Landing page |
| `/signin` | Flow switcher — Widget or OIDC |
| `/profile` | Protected profile page (both flows) |
| `/api/auth/widget-finalize` | Exchanges auth code for tokens (widget flow) |
| `/api/auth/widget-logout` | Clears widget session + server-to-server logout |
| `/api/auth/[...nextauth]` | Auth.js route handler (OIDC flow) |

## Flows

**Widget flow** — `<zero-account>` custom element handles PKCE, QR code, and SSE session.
Your backend needs one `POST /api/auth/widget-finalize` endpoint.

**OIDC flow** — Auth.js with 0account as OIDC provider. Handles state, PKCE, token refresh, and sessions automatically.

## Setup

```bash
cp .env.example .env.local
# Fill in the values (see below)

npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `CLIENT_ID` | ✅ | Your OAuth client ID from the 0account dashboard |
| `CLIENT_SECRET` | ✅ | Your OAuth client secret |
| `AUTH_SECRET` | ✅ | Random secret for Auth.js — generate with `npx auth secret` |
| `NEXT_PUBLIC_APP_ID` | ✅ | Same as `CLIENT_ID` — used by the `<zero-account>` element |
| `NEXT_PUBLIC_REDIRECT_URI` | ✅ | Redirect URI registered in your 0account app (e.g. `http://localhost:3000/auth/callback`) |

## Register in 0account dashboard

Add these URIs to your app:

- **Redirect URI**: `http://localhost:3000/auth/callback`
- **Back-channel logout URI** (optional): `http://localhost:3000/api/auth/widget-logout`
