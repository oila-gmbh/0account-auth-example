import Link from "next/link"

export default function HomePage() {
  return (
    <main className="flex flex-1 flex-col items-center justify-center px-4 py-20">
      <div className="w-full max-w-2xl text-center">
        <p className="mb-3 text-sm font-medium uppercase tracking-widest text-zinc-500">
          0account
        </p>
        <h1 className="mb-4 text-4xl font-bold tracking-tight text-zinc-50">
          Auth Examples
        </h1>
        <p className="mb-10 text-lg text-zinc-400">
          Two authentication flows, one showcase. Widget flow for zero-redirect
          QR sign-in. OIDC flow for standard Auth.js integration.
        </p>

        <Link
          href="/signin"
          className="inline-flex items-center gap-2 rounded-xl bg-zinc-50 px-8 py-3.5 font-semibold text-zinc-950 transition-colors hover:bg-zinc-200"
        >
          Try it →
        </Link>

        <div className="mt-16 grid gap-4 text-left sm:grid-cols-2">
          <FlowCard
            title="Widget Flow"
            description="The &lt;zero-account&gt; custom element handles PKCE, QR code display, and the SSE session. Your backend needs one endpoint to exchange the code for tokens."
            badge="No redirects"
          />
          <FlowCard
            title="OIDC Flow"
            description="Standard OpenID Connect via Auth.js. Handles state, PKCE, token refresh, and secure sessions automatically. Works with any OIDC-compatible provider."
            badge="Auth.js"
          />
        </div>
      </div>
    </main>
  )
}

function FlowCard({
  title,
  description,
  badge,
}: {
  title: string
  description: string
  badge: string
}) {
  return (
    <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
      <span className="mb-3 inline-block rounded-full bg-zinc-800 px-2.5 py-0.5 text-xs font-medium text-zinc-300">
        {badge}
      </span>
      <h2 className="mb-2 font-semibold text-zinc-50">{title}</h2>
      <p className="text-sm text-zinc-400">{description}</p>
    </div>
  )
}
