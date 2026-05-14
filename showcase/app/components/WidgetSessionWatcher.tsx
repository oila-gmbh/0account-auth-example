"use client"

import { useEffect } from "react"

function getSessionTokenKey(appId: string): string {
  const hash = btoa(appId).substring(0, 24).replace(/=/g, "")
  return `_za_st_${hash}`
}

type Props = { appId: string }

/**
 * Invisible client component that subscribes to the 0account SSE session stream.
 *
 * When the user logs out from the 0account mobile app (or another device), the
 * server fires a logout event over SSE. This component detects it and
 * automatically clears the local session, then redirects to /signin.
 *
 * Mount this on any page where a widget-flow user must be kept in sync with
 * their remote 0account session state.
 */
export default function WidgetSessionWatcher({ appId }: Props) {
  useEffect(() => {
    const key = getSessionTokenKey(appId)
    const sessionToken = localStorage.getItem(key)
    if (!sessionToken) return

    const controller = new AbortController()

    async function connect() {
      try {
        const res = await fetch("https://v1.0account.com/users/profiles/me/session/stream", {
          headers: { Authorization: `Bearer ${sessionToken}` },
          signal: controller.signal,
        })
        if (!res.ok || !res.body) return

        const reader = res.body.getReader()
        const decoder = new TextDecoder()
        let buffer = ""

        while (true) {
          const { value, done } = await reader.read()
          if (done) break
          buffer += decoder.decode(value, { stream: true })
          const lines = buffer.split("\n")
          buffer = lines.pop() ?? ""
          for (const line of lines) {
            if (!line.startsWith("data:")) continue
            try {
              const event = JSON.parse(line.slice(5).trim()) as { action?: string }
              if (event.action === "logout") {
                localStorage.removeItem(key)
                await fetch("/api/auth/widget-logout").catch(() => {})
                window.location.href = "/signin"
                return
              }
            } catch {
              // malformed SSE data line — skip
            }
          }
        }
      } catch {
        // AbortError on cleanup or network issue — ignore
      }
    }

    connect()
    return () => controller.abort()
  }, [appId])

  return null
}
