import { auth, signOut } from "@/auth"
import { cookies } from "next/headers"
import { redirect } from "next/navigation"
import SignOutButtons from "../components/SignOutButtons"

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

export default async function ProfilePage() {
  const [session, cookieStore] = await Promise.all([auth(), cookies()])

  const rawCookie = cookieStore.get("widget_session")?.value
  const widgetSession: WidgetSession | null = rawCookie
    ? (JSON.parse(rawCookie) as WidgetSession)
    : null

  if (!session && !widgetSession) redirect("/signin")

  const isOidc = !!session
  const userName = isOidc ? (session?.user?.name ?? "—") : (widgetSession?.name ?? "—")
  const email = isOidc ? (session?.user?.email ?? "—") : (widgetSession?.email ?? "—")
  const userId = isOidc ? (session?.user?.id ?? "—") : (widgetSession?.sub ?? "—")
  const flow = isOidc ? "OIDC (Auth.js)" : "Widget Flow"

  async function oidcSignOut() {
    "use server"
    await signOut({ redirectTo: "/" })
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
        <div className="mb-6 space-y-2">
          <InfoRow label="Auth flow" value={flow} />
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

        <SignOutButtons isOidc={isOidc} oidcSignOut={oidcSignOut} />
      </div>
    </main>
  )
}
