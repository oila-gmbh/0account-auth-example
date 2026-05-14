"use client"

import { useRouter } from "next/navigation"

type Props = {
  isOidc: boolean
  oidcSignOut: () => Promise<void>
}

export default function SignOutButtons({ isOidc, oidcSignOut }: Props) {
  const router = useRouter()

  if (isOidc) {
    return (
      <form action={oidcSignOut}>
        <button
          type="submit"
          className="w-full rounded-xl border border-zinc-700 px-4 py-2.5 text-sm text-zinc-300 transition-colors hover:bg-zinc-800"
        >
          Sign out
        </button>
      </form>
    )
  }

  return (
    <div className="space-y-2">
      {/* Front-channel logout: terminates the 0account session via POST /oauth/logout */}
      <button
        onClick={async () => {
          await fetch("/api/auth/widget-logout")
          router.push("/")
        }}
        className="w-full rounded-xl border border-zinc-700 px-4 py-2.5 text-sm text-zinc-300 transition-colors hover:bg-zinc-800"
      >
        Sign out (widget)
      </button>

      {/*
        Back-channel demo: simulates 0account calling our backchannel_logout_uri.
        Adds the sub to revokedSubs server-side WITHOUT clearing the cookie, then
        redirects to /profile. The server component detects the revocation and
        redirects to /api/auth/widget-logout which clears the cookie.
      */}
      <button
        onClick={() => {
          window.location.href = "/api/auth/backchannel-logout-test"
        }}
        className="w-full rounded-xl border border-zinc-700 px-4 py-2.5 text-sm text-zinc-400 transition-colors hover:bg-zinc-800"
        title="Simulates 0account calling your backchannel_logout_uri"
      >
        Sign out (back-channel demo)
      </button>
    </div>
  )
}

