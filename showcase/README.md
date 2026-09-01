# Showcase — 0account Auth Example

A Next.js App Router app demonstrating both 0account authentication flows side by side.

## What's inside

| Route | Description |
|---|---|
| `/` | Landing page |
| `/signin` | Pick a backend and sign in |
| `/profile` | Protected profile page (both flows) |
| `/api/auth/[...nextauth]` | Auth.js route handler (OIDC flow) |

## Flows


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
| `ZERO_CLIENT_ID` | ✅ | Your OAuth client ID from the 0account dashboard |
| `ZERO_CLIENT_SECRET` | ✅ | Your OAuth client secret |
| `AUTH_SECRET` | ✅ | Random secret for Auth.js — generate with `npx auth secret` |
| `NEXT_PUBLIC_APP_ID` | ✅ | Same as `ZERO_CLIENT_ID` — used by the `<zero-account>` element |
| `NEXT_PUBLIC_REDIRECT_URI` | ✅ | Redirect URI registered in your 0account app (e.g. `http://localhost:3000/auth/callback`) |

## Register in 0account dashboard

Add these URIs to your app:

- **Redirect URI**: `http://localhost:3000/auth/callback`
