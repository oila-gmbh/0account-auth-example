"use client"

import { useEffect, useState, useCallback } from "react"
import { useRouter } from "next/navigation"

type Integration = {
  name: string
  language: string
  flow: string
  library: string
  url: string
}

type MeResponse = {
  userId: string
  email: string
  name: string
  integration: Integration
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-4 rounded-lg bg-zinc-800/50 px-3 py-2">
      <span className="text-sm text-zinc-400 whitespace-nowrap">{label}</span>
      <span className="font-mono text-sm text-zinc-200 truncate max-w-[200px]">{value}</span>
    </div>
  )
}

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${color}`}
    >
      {label}
    </span>
  )
}

const LANGUAGE_COLORS: Record<string, string> = {
  "Node.js": "bg-green-900/50 text-green-300",
  Go: "bg-cyan-900/50 text-cyan-300",
  "Next.js": "bg-blue-900/50 text-blue-300",
}

const FLOW_COLORS: Record<string, string> = {
  widget: "bg-purple-900/50 text-purple-300",
  oidc: "bg-orange-900/50 text-orange-300",
}

export default function ExternalProfile({ backendUrl }: { backendUrl: string }) {
  const router = useRouter()
  const [data, setData] = useState<MeResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  const logout = useCallback(() => {
    const returnTo = encodeURIComponent(window.location.origin + "/signin")
    window.location.href = `${backendUrl}/auth/logout?return_to=${returnTo}`
  }, [backendUrl])

  useEffect(() => {
    let mounted = true

    async function fetchMe() {
      try {
        const res = await fetch(`${backendUrl}/auth/me`, { credentials: "include" })
        if (!res.ok) {
          router.replace("/signin")
          return
        }
        const json = (await res.json()) as MeResponse
        if (mounted) setData(json)
      } catch {
        if (mounted) setError("Failed to reach backend")
      }
    }

    fetchMe()

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${backendUrl}/auth/status`, { credentials: "include" })
        if (res.status === 401) {
          clearInterval(interval)
          router.replace("/signin")
        }
      } catch {
        // network error — keep polling
      }
    }, 3000)

    return () => {
      mounted = false
      clearInterval(interval)
    }
  }, [backendUrl, router])

  if (error) {
    return (
      <main className="flex flex-1 flex-col items-center justify-center px-4 py-12">
        <div className="w-full max-w-md rounded-2xl border border-zinc-800 bg-zinc-900/40 p-8 text-center">
          <p className="text-red-400">{error}</p>
        </div>
      </main>
    )
  }

  if (!data) {
    return (
      <main className="flex flex-1 flex-col items-center justify-center px-4 py-12">
        <div className="w-full max-w-md rounded-2xl border border-zinc-800 bg-zinc-900/40 p-8 text-center">
          <p className="text-zinc-400 text-sm">Loading session…</p>
        </div>
      </main>
    )
  }

  const { userId, email, name, integration } = data
  const langColor = LANGUAGE_COLORS[integration.language] ?? "bg-zinc-800 text-zinc-300"
  const flowColor = FLOW_COLORS[integration.flow] ?? "bg-zinc-800 text-zinc-300"

  return (
    <main className="flex flex-1 flex-col items-center justify-center px-4 py-12">
      <div className="w-full max-w-md rounded-2xl border border-zinc-800 bg-zinc-900/40 p-8">
        {/* Avatar + name */}
        <div className="mb-6 flex items-center gap-4">
          <div className="flex size-12 items-center justify-center rounded-full bg-zinc-700 text-xl font-bold text-zinc-50">
            {name?.[0]?.toUpperCase() ?? "U"}
          </div>
          <div>
            <p className="font-semibold text-zinc-50">{name}</p>
            <p className="text-sm text-zinc-400">{email}</p>
          </div>
        </div>

        {/* Session info */}
        <div className="mb-4 space-y-2">
          <InfoRow label="User ID" value={userId} />
        </div>

        {/* Integration metadata */}
        <div className="mb-6 rounded-xl border border-zinc-800 bg-zinc-800/30 p-4 space-y-3">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-zinc-100">{integration.name}</span>
            <Badge label={integration.language} color={langColor} />
            <Badge label={integration.flow} color={flowColor} />
          </div>
          <div className="space-y-1.5 text-xs">
            <div className="flex justify-between gap-2">
              <span className="text-zinc-500">Library</span>
              <span className="font-mono text-zinc-300">{integration.library}</span>
            </div>
            <div className="flex justify-between gap-2">
              <span className="text-zinc-500">Backend URL</span>
              <span className="font-mono text-zinc-300 truncate max-w-[200px]">{integration.url}</span>
            </div>
          </div>
        </div>

        <button
          onClick={logout}
          className="w-full rounded-xl border border-zinc-700 bg-transparent px-4 py-2.5 text-sm text-zinc-400 transition-colors hover:bg-zinc-800 hover:text-zinc-100"
        >
          Sign out
        </button>
      </div>
    </main>
  )
}
