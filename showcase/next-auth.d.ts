import type { DefaultSession } from "next-auth"

declare module "next-auth" {
  interface Session extends DefaultSession {
    accessToken?: string
    /** The 0account session id, carried over from the ID token's sid claim. */
    sid?: string
    error?: string
    user: {
      id?: string
    } & DefaultSession["user"]
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    /** The per-app subject. Auth.js's own `sub` is a random UUID it generated. */
    zeroSub?: string
    zeroSid?: string
    accessToken?: string
    idToken?: string
    refreshToken?: string
    expiresAt?: number
    error?: string
  }
}
