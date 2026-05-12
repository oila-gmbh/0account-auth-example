"use client"

import { Suspense, useEffect, useRef } from "react"
import { useSearchParams, useRouter } from "next/navigation"
import { signIn } from "next-auth/react"
import "@0account/web"

type Tab = "widget" | "oidc"

type OidcProvider = {
  id: string
  label: string
  description: string
  onClick?: () => void
  url: string | null
}

const oidcProviders: OidcProvider[] = [
  {
    id: "nextauth",
    label: "Auth.js (next-auth)",
    description: "Token refresh, session management out of the box.",
    onClick: () => signIn("0account", { callbackUrl: "/profile" }),
    url: null,
  },
  {
    id: "passport",
    label: "Passport.js",
    description: "Express + passport-openidconnect strategy.",
    url: process.env.NEXT_PUBLIC_PASSPORT_URL
      ? `${process.env.NEXT_PUBLIC_PASSPORT_URL}/auth/login`
      : null,
  },
  {
    id: "openid-client",
    label: "openid-client",
    description: "Low-level OIDC client for Node.js.",
    url: process.env.NEXT_PUBLIC_OPENID_CLIENT_URL
      ? `${process.env.NEXT_PUBLIC_OPENID_CLIENT_URL}/auth/login`
      : null,
  },
  {
    id: "go-oidc",
    label: "Go (go-oidc)",
    description: "Minimal OIDC flow in Go with coreos/go-oidc.",
    url: process.env.NEXT_PUBLIC_GO_OIDC_URL
      ? `${process.env.NEXT_PUBLIC_GO_OIDC_URL}/auth/login`
      : null,
  },
  {
    id: "goth",
    label: "Go (Goth)",
    description: "Multi-provider OAuth2 library for Go.",
    url: process.env.NEXT_PUBLIC_GO_GOTH_URL
      ? `${process.env.NEXT_PUBLIC_GO_GOTH_URL}/auth/login`
      : null,
  },
]

function SignInContent() {
  const searchParams = useSearchParams()
  const router = useRouter()
  const activeTab: Tab = searchParams.get("flow") === "oidc" ? "oidc" : "widget"
  const widgetRef = useRef<HTMLElement | null>(null)

  const setActiveTab = (tab: Tab) => {
    router.replace(`/signin?flow=${tab}`, { scroll: false })
  }

  useEffect(() => {
    const el = widgetRef.current
    if (!el) return
    const handler = () => {
      window.location.href = "/profile"
    }
    el.addEventListener("0account-authenticated", handler)
    return () => el.removeEventListener("0account-authenticated", handler)
  }, [activeTab])

  return (
    <main className="flex flex-1 flex-col items-center justify-center px-4 py-12">
      <div className={`w-full ${activeTab === "oidc" ? "max-w-lg" : "max-w-md"}`}>
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
              app-id={process.env.NEXT_PUBLIC_CLIENT_ID}
              redirect-uri={
                process.env.NEXT_PUBLIC_REDIRECT_URI ??
                "http://localhost:3000/auth/callback"
              }
              finalize-uri="/api/auth/widget-finalize"
              scope="openid profile email offline_access"
              with-button
              style={{ display: "block", width: "100%", maxWidth: "360px" }}
            />
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            <p className="mb-3 text-center text-sm text-zinc-400">
              Standard OIDC redirect flow. Choose a backend implementation to
              see how each handles the auth cycle.
            </p>
            {oidcProviders.map((provider) => {
              const disabled = !provider.onClick && !provider.url
              return (
                <button
                  key={provider.id}
                  disabled={disabled}
                  title={disabled ? "Run docker-compose to enable" : undefined}
                  onClick={() => {
                    if (provider.onClick) {
                      provider.onClick()
                    } else if (provider.url) {
                      window.location.href = provider.url
                    }
                  }}
                  className={`w-full rounded-xl px-6 py-4 text-left transition-colors ${
                    disabled
                      ? "cursor-not-allowed bg-zinc-800 opacity-50"
                      : "bg-zinc-800 hover:bg-zinc-700"
                  }`}
                >
                  <div className="font-medium text-zinc-50">{provider.label}</div>
                  <div className="mt-0.5 text-sm text-zinc-400">{provider.description}</div>
                </button>
              )
            })}
          </div>
        )}
      </div>
    </main>
  )
}

export default function SignInPage() {
  return (
    <Suspense>
      <SignInContent />
    </Suspense>
  )
}
