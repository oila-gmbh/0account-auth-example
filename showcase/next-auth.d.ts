import type { DefaultSession } from "next-auth"

declare module "next-auth" {
  interface Session extends DefaultSession {
    accessToken?: string
    error?: string
    user: {
      id?: string
    } & DefaultSession["user"]
  }
}
