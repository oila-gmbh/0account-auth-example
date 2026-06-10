import { signOut } from "@/auth"

/**
 * GET /api/auth/oidc-logout
 *
 * Clears the Auth.js session cookie and redirects to /signin.
 * Used by OidcSessionPoller and the profile page when a revocation is detected.
 */
export async function GET() {
  await signOut({ redirectTo: "/signin" })
}
