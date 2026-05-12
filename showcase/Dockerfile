# ── Stage 1: install dependencies ────────────────────────────────────────────
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci

# ── Stage 2: build ────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# NEXT_PUBLIC_* vars are inlined at build time — pass them via --build-arg.
ARG NEXT_PUBLIC_APP_ID
ARG NEXT_PUBLIC_REDIRECT_URI
ARG NEXT_PUBLIC_APP_URL
ENV NEXT_PUBLIC_APP_ID=$NEXT_PUBLIC_APP_ID
ENV NEXT_PUBLIC_REDIRECT_URI=$NEXT_PUBLIC_REDIRECT_URI
ENV NEXT_PUBLIC_APP_URL=$NEXT_PUBLIC_APP_URL

ARG NEXT_PUBLIC_PASSPORT_URL
ARG NEXT_PUBLIC_OPENID_CLIENT_URL
ARG NEXT_PUBLIC_GO_OIDC_URL
ARG NEXT_PUBLIC_GO_GOTH_URL
ENV NEXT_PUBLIC_PASSPORT_URL=$NEXT_PUBLIC_PASSPORT_URL
ENV NEXT_PUBLIC_OPENID_CLIENT_URL=$NEXT_PUBLIC_OPENID_CLIENT_URL
ENV NEXT_PUBLIC_GO_OIDC_URL=$NEXT_PUBLIC_GO_OIDC_URL
ENV NEXT_PUBLIC_GO_GOTH_URL=$NEXT_PUBLIC_GO_GOTH_URL

RUN npm run build

# ── Stage 3: production runner ────────────────────────────────────────────────
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs \
 && adduser  --system --uid 1001 nextjs

COPY --from=builder /app/public ./public

# standalone output bundles server.js + its dependencies
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static     ./.next/static

USER nextjs
EXPOSE 3000
ENV PORT=3000 \
    HOSTNAME="0.0.0.0"

CMD ["node", "server.js"]
