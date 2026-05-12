"use client"

import { useState, useEffect, useRef } from "react"
import { signIn } from "next-auth/react"
import "@0account/web"

type Tab = "widget" | "oidc"

export default function SignInPage() {
  const [activeTab, setActiveTab] = useState<Tab>("widget")
  const widgetRef = useRef<HTMLElement | null>(null)

  useEffect(() => {
    const el = widgetRef.current
    if (!el) return
    const handler = () => {
      // The widget has already POSTed to /api/auth/widget-finalize and the
      // server set the widget_session cookie. Navigate to the profile page.
      window.location.href = "/profile"
    }
    el.addEventListener("0account-authenticated", handler)
    return () => el.removeEventListener("0account-authenticated", handler)
  }, [activeTab])

  return (
    <main className="flex flex-1 flex-col items-center justify-center px-4 py-12">
      <div className="w-full max-w-md">
        <h1 className="mb-8 text-center text-2xl font-semibold text-zinc-50">
          Sign in
        </h1>

        {/* Flow switcher */}
        <div className="mb-8 flex rounded-xl bg-zinc-900 p-1">
          {(["widget", "oidc"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`flex-1 rounded-lg px-4 py-2.5 text-sm font-medium transition-colors ${
                activeTab === tab
                  ? "bg-zinc-700 text-zinc-50 shadow"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              {tab === "widget" ? "Widget Flow" : "OIDC Flow"}
            </button>
          ))}
        </div>

        {activeTab === "widget" ? (
          <div className="flex flex-col items-center gap-6">
            <p className="text-center text-sm text-zinc-400">
              The widget handles PKCE, QR code, and the SSE session. Your
              backend only needs one finalize endpoint.
            </p>
            <zero-account
              ref={widgetRef}
              app-id={process.env.NEXT_PUBLIC_APP_ID}
              redirect-uri={
                process.env.NEXT_PUBLIC_REDIRECT_URI ??
                "http://localhost:3000/auth/callback"
              }
              finalize-uri="/api/auth/widget-finalize"
              scope="openid profile email offline_access"
              with-button
            />
          </div>
        ) : (
          <div className="flex flex-col items-center gap-6">
            <p className="text-center text-sm text-zinc-400">
              Standard OIDC via Auth.js. Handles redirect, state, PKCE, token
              refresh, and session automatically.
            </p>
            <button
              onClick={() => signIn("0account", { callbackUrl: "/profile" })}
              className="w-full rounded-xl bg-zinc-50 px-6 py-3 font-medium text-zinc-950 transition-colors hover:bg-zinc-200"
            >
              Sign in with 0account
            </button>
          </div>
        )}
      </div>
    </main>
  )
}
