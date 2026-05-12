# 0account Auth Examples

Authentication examples for [0account](https://0account.com) — covering the widget flow and OIDC
flow across Go and Node.js backends, plus a full-stack Next.js showcase.

## Structure

```
showcase/          Next.js App Router — Widget + OIDC side-by-side demo
go/
  widget/          Go Fiber — widget flow backend
  goth/            Go + goth — OIDC (simplest Go option)
  go-oidc/         Go + coreos/go-oidc — OIDC with full control
nodejs/
  widget/          Express — widget flow backend
  openid-client/   Express + openid-client — OIDC with full control
  passport/        Express + Passport.js — OIDC, familiar middleware style
```

## Quick start

### Showcase (Next.js)

```bash
cd showcase
cp .env.example .env.local   # fill in credentials
npm install
npm run dev
# → http://localhost:3000
```

### Go examples

```bash
cd go/<example>
cp .env.example .env         # fill in credentials
go mod tidy
go run main.go
# → http://localhost:8080
```

### Node.js examples

```bash
cd nodejs/<example>
cp .env.example .env         # fill in credentials
npm install
npm run dev
# → http://localhost:3000
```

## Environment variables (common)

| Variable | Description |
|---|---|
| `CLIENT_ID` | OAuth client ID from the 0account dashboard |
| `CLIENT_SECRET` | OAuth client secret |
| `SESSION_SECRET` | Random string for signing session cookies |
| `AUTH_SECRET` | Auth.js secret — generate with `npx auth secret` (showcase only) |
| `NEXT_PUBLIC_APP_ID` | Same as `CLIENT_ID` — used by `<zero-account>` element (showcase only) |
| `NEXT_PUBLIC_REDIRECT_URI` | Registered redirect URI for widget flow (showcase only) |

## Examples at a glance

| Example | Flow | Stack | Port |
|---|---|---|---|
| `showcase/` | Widget + OIDC | Next.js 15, Auth.js, `@0account/web` | 3000 |
| `go/widget/` | Widget | Go, Fiber v2 | 8080 |
| `go/goth/` | OIDC | Go, goth | 8080 |
| `go/go-oidc/` | OIDC | Go, coreos/go-oidc, oauth2 | 8080 |
| `nodejs/widget/` | Widget | Node.js, Express | 3000 |
| `nodejs/openid-client/` | OIDC | Node.js, Express, openid-client | 3000 |
| `nodejs/passport/` | OIDC | Node.js, Express, Passport.js | 3000 |

## 0account dashboard setup

For each example register:

- **Redirect URI**: matching the port/path of the example (see READMEs)
- **Back-channel logout URI** (optional): `<base>/auth/backchannel-logout` or `<base>/api/auth/widget-logout`

## API reference

All examples target `https://v1.0account.com`. Key endpoints used:

| Endpoint | Description |
|---|---|
| `POST /oauth/token` | Exchange code or refresh token |
| `GET /oauth/userinfo` | Fetch authenticated user's profile |
| `POST /oauth/logout` | Server-to-server session termination |
| `GET /.well-known/openid-configuration` | OIDC discovery document |
