"use client"

import { useEffect } from "react"

/**
 * Invisible client component that polls /api/auth/status every 3 seconds.
 *
 * When a 401 is received (session revoked or expired), it redirects to the
 * OIDC logout route, which clears the Auth.js session cookie before sending
 * the user back to /signin.
 *
 * Mount on any page where an OIDC-flow user must be kept in sync with their
 * remote 0account session state (i.e. wherever back-channel logout should
 * cause an immediate redirect).
 */
export default function OidcSessionPoller() {
  useEffect(() => {
    const t = setInterval(async () => {
      try {
        const r = await fetch("/api/auth/status")
        if (r.status === 401) {
          clearInterval(t)
          window.location.href = "/api/auth/oidc-logout"
        }
      } catch {
        // network error — retry next tick
      }
    }, 3000)
    return () => clearInterval(t)
  }, [])

  return null
}
