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
    <button
      onClick={async () => {
        await fetch("/api/auth/widget-logout")
        router.push("/")
      }}
      className="w-full rounded-xl border border-zinc-700 px-4 py-2.5 text-sm text-zinc-300 transition-colors hover:bg-zinc-800"
    >
      Sign out
    </button>
  )
}
