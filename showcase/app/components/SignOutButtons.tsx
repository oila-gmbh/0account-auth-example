"use client"

type Props = {
  oidcSignOut: () => Promise<void>
}

export default function SignOutButtons({ oidcSignOut }: Props) {
  return (
    <div className="flex flex-col gap-2">
      <form action={oidcSignOut}>
        <button
          type="submit"
          className="w-full rounded-xl border border-zinc-700 px-4 py-2.5 text-sm text-zinc-300 transition-colors hover:bg-zinc-800"
        >
          Sign out
        </button>
      </form>

      {/*
        Simulates 0account calling your backchannel_logout_uri — what happens when
        the user ends this session from their phone, rather than from here.
      */}
      <button
        onClick={() => {
          window.location.href = "/api/auth/backchannel-logout-test"
        }}
        className="w-full rounded-xl border border-zinc-800 px-4 py-2.5 text-sm text-zinc-500 transition-colors hover:bg-zinc-900"
        title="Simulates 0account calling your backchannel_logout_uri"
      >
        Sign out (back-channel demo)
      </button>
    </div>
  )
}
