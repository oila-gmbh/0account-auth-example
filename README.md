# 0account Auth Examples

Authentication examples for [0account](https://0account.com), a standard OpenID Connect provider
flow across Go and Node.js backends, plus a full-stack Next.js showcase.

## Structure

```
showcase/          Next.js App Router — sign-in, profile, logout, back-channel
go/
  goth/            Go + goth — OIDC (simplest Go option)
  go-oidc/         Go + coreos/go-oidc — OIDC with full control
nodejs/
  openid-client/   Express + openid-client — OIDC with full control
  passport/        Express + Passport.js — OIDC, familiar middleware style
```

## Quick start

### Local (no Docker)

```bash
cd showcase
cp .env.example .env.local   # fill in credentials
npm install
npm run dev
# → http://localhost:3000
```

### Docker (showcase only)

```bash
cp .env.example .env         # fill in credentials
docker-compose up --build
# → http://localhost:3000
```

The `NEXT_PUBLIC_*` variables are inlined at build time. After changing them,
rebuild with `docker-compose up --build`.

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
| `ZERO_CLIENT_ID` | OAuth client ID from the 0account dashboard |
| `ZERO_CLIENT_SECRET` | OAuth client secret |
| `SESSION_SECRET` | Random string for signing session cookies |
| `AUTH_SECRET` | Auth.js secret — generate with `npx auth secret` (showcase only) |
| `NEXT_PUBLIC_APP_ID` | Same as `ZERO_CLIENT_ID` — used by `<zero-account>` element (showcase only) |
| `NEXT_PUBLIC_REDIRECT_URI` | Registered redirect URI (showcase only) |

## Examples at a glance

| Example | Flow | Stack | Port |
|---|---|---|---|
| `showcase/` | OIDC | Next.js 15, Auth.js | 3000 |
| `go/goth/` | OIDC | Go, goth | 8080 |
| `go/go-oidc/` | OIDC | Go, coreos/go-oidc, oauth2 | 8080 |
| `nodejs/openid-client/` | OIDC | Node.js, Express, openid-client | 3000 |
| `nodejs/passport/` | OIDC | Node.js, Express, Passport.js | 3000 |

## 0account dashboard setup

For each example register:

- **Redirect URI**: matching the port/path of the example (see READMEs)
- **Back-channel logout URI** (optional): `<base>/auth/backchannel-logout`

## API reference

All examples target `https://v1.0account.com`. Key endpoints used:

| Endpoint | Description |
|---|---|
| `POST /oauth/token` | Exchange code or refresh token |
| `GET /oauth/userinfo` | Fetch authenticated user's profile |
| `POST /oauth/logout` | Server-to-server session termination |
| `GET /.well-known/openid-configuration` | OIDC discovery document |
