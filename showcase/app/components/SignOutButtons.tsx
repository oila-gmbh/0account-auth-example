"use client"

type Props = {
  isOidc: boolean
  oidcSignOut: () => Promise<void>
}

export default function SignOutButtons({ isOidc, oidcSignOut }: Props) {
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
    <div>
      {/*
        Back-channel demo: simulates 0account calling our backchannel_logout_uri.
        Sets a revocation cookie server-side WITHOUT clearing the widget session, then
        redirects to /profile. The server component detects the revocation and
        redirects to /api/auth/widget-logout which clears the cookie.
        SSE-based auto-logout (when the user signs out on another device) is handled
        transparently by <WidgetSessionWatcher />.
      */}
      <button
        onClick={() => {
          window.location.href = "/api/auth/backchannel-logout-test"
        }}
        className="w-full rounded-xl border border-zinc-700 px-4 py-2.5 text-sm text-zinc-300 transition-colors hover:bg-zinc-800"
        title="Simulates 0account calling your backchannel_logout_uri"
      >
        Sign out (back-channel demo)
      </button>
    </div>
  )
}

