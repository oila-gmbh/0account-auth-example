import { auth, signOut } from "@/auth"
import { cookies } from "next/headers"
import { redirect } from "next/navigation"
import SignOutButtons from "../components/SignOutButtons"
import OidcSessionPoller from "../components/OidcSessionPoller"
import ExternalProfile from "../components/ExternalProfile"
import { revokedSubs } from "@/app/lib/revokedSubs"

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

  // Showcase-native flow (Auth.js OIDC)
  const [session, cookieStore] = await Promise.all([auth(), cookies()])


  if (!session) redirect("/signin")


  if (session?.user?.id && revokedSubs.has(session.user.id)) {
    redirect("/api/auth/oidc-logout")
  }

  const userName = session?.user?.name ?? "—"
  const email = session?.user?.email ?? "—"
  const userId = session?.user?.id ?? "—"

  const integration = { name: "Auth.js", language: "Next.js", flow: "oidc", library: "next-auth" }

  const langColor = "bg-blue-900/50 text-blue-300"
  const flowColor = "bg-orange-900/50 text-orange-300"

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
          {session?.accessToken && (
            <InfoRow
              label="Access token"
              value={`${session.accessToken.slice(0, 28)}…`}
            />
          )}
          {session?.error === "RefreshAccessTokenError" && (
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

        <SignOutButtons oidcSignOut={oidcSignOut} />
        <OidcSessionPoller />
      </div>
    </main>
  )
}
