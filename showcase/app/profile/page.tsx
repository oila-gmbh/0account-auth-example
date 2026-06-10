import { auth, signOut } from "@/auth"
import { cookies } from "next/headers"
import { redirect } from "next/navigation"
import SignOutButtons from "../components/SignOutButtons"
import WidgetSessionWatcher from "../components/WidgetSessionWatcher"
import OidcSessionPoller from "../components/OidcSessionPoller"
import ExternalProfile from "../components/ExternalProfile"
import { revokedSubs } from "@/app/lib/revokedSubs"

type WidgetSession = {
  sub: string
  email: string
  name: string
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-4 rounded-lg bg-zinc-800/50 px-3 py-2">
      <span className="text-sm text-zinc-400">{label}</span>
      <span className="font-mono text-sm text-zinc-200 truncate">{value}</span>
    </div>
  )
}

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${color}`}>
      {label}
    </span>
  )
}

type SearchParams = Promise<Record<string, string | string[] | undefined>>

export default async function ProfilePage({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams
  const externalUrl = typeof params.url === "string" ? params.url : undefined

  // External backend flow: delegate entirely to the client component
  if (externalUrl) {
    return <ExternalProfile backendUrl={externalUrl} />
  }

  // Showcase-native flows (Auth.js OIDC + showcase widget)
  const [session, cookieStore] = await Promise.all([auth(), cookies()])

  const rawCookie = cookieStore.get("widget_session")?.value
  const widgetSession: WidgetSession | null = rawCookie
    ? (JSON.parse(rawCookie) as WidgetSession)
    : null

  if (!session && !widgetSession) redirect("/signin")

  if (widgetSession && (revokedSubs.has(widgetSession.sub) || cookieStore.get("_bcl_revoked")?.value === "1")) {
    redirect("/api/auth/widget-logout")
  }

  if (session?.user?.id && revokedSubs.has(session.user.id)) {
    redirect("/api/auth/oidc-logout")
  }

  const isOidc = !!session
  const userName = isOidc ? (session?.user?.name ?? "—") : (widgetSession?.name ?? "—")
  const email = isOidc ? (session?.user?.email ?? "—") : (widgetSession?.email ?? "—")
  const userId = isOidc ? (session?.user?.id ?? "—") : (widgetSession?.sub ?? "—")

  const integration = isOidc
    ? { name: "Auth.js", language: "Next.js", flow: "oidc", library: "next-auth" }
    : { name: "Showcase Widget", language: "Next.js", flow: "widget", library: "@0account/web" }

  const langColor = "bg-blue-900/50 text-blue-300"
  const flowColor = isOidc ? "bg-orange-900/50 text-orange-300" : "bg-purple-900/50 text-purple-300"

  async function oidcSignOut() {
    "use server"
    await signOut({ redirectTo: "/signin" })
  }

  return (
    <main className="flex flex-1 flex-col items-center justify-center px-4 py-12">
      <div className="w-full max-w-md rounded-2xl border border-zinc-800 bg-zinc-900/40 p-8">
        {/* Avatar + name */}
        <div className="mb-6 flex items-center gap-4">
          <div className="flex size-12 items-center justify-center rounded-full bg-zinc-700 text-xl font-bold text-zinc-50">
            {userName[0]?.toUpperCase() ?? "U"}
          </div>
          <div>
            <p className="font-semibold text-zinc-50">{userName}</p>
            <p className="text-sm text-zinc-400">{email}</p>
          </div>
        </div>

        {/* Session info */}
        <div className="mb-4 space-y-2">
          <InfoRow label="User ID" value={userId} />
          {isOidc && session?.accessToken && (
            <InfoRow
              label="Access token"
              value={`${session.accessToken.slice(0, 28)}…`}
            />
          )}
          {isOidc && session?.error === "RefreshAccessTokenError" && (
            <p className="rounded-lg bg-red-950/40 px-3 py-2 text-sm text-red-400">
              Token refresh failed. Please sign in again.
            </p>
          )}
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
          </div>
        </div>

        <SignOutButtons isOidc={isOidc} oidcSignOut={oidcSignOut} />
        {isOidc && <OidcSessionPoller />}
        {!isOidc && process.env.NEXT_PUBLIC_CLIENT_ID && (
          <WidgetSessionWatcher appId={process.env.NEXT_PUBLIC_CLIENT_ID} />
        )}
      </div>
    </main>
  )
}
