'use client';

import { Suspense, useEffect, useState } from 'react';
import { signIn } from 'next-auth/react';
import AuthError from '../components/AuthError';

// ─── Badge helpers ────────────────────────────────────────────────────────────

function LangBadge({ lang }: { lang: string }) {
  const color =
    lang === 'Node.js' ? 'bg-green-900/50 text-green-300' :
    lang === 'Go'      ? 'bg-cyan-900/50 text-cyan-300' :
                         'bg-blue-900/50 text-blue-300';
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium ${color}`}>
      {lang}
    </span>
  );
}

function FlowBadge({ flow }: { flow: 'oidc' }) {
  const color = 'bg-violet-500/10 text-violet-300 ring-violet-500/20';
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium ${color}`}>
      {flow}
    </span>
  );
}

// ─── Copy button ─────────────────────────────────────────────────────────────

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <button
      onClick={copy}
      title="Copy"
      className="ml-1 shrink-0 rounded p-0.5 text-zinc-600 hover:text-zinc-300 transition-colors"
    >
      {copied ? (
        <svg width="11" height="11" viewBox="0 0 16 16" fill="currentColor"><path d="M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.75.75 0 0 1 1.06-1.06L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0Z"/></svg>
      ) : (
        <svg width="11" height="11" viewBox="0 0 16 16" fill="currentColor"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 0 1 0 1.5h-1.5a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-1.5a.75.75 0 0 1 1.5 0v1.5A1.75 1.75 0 0 1 9.25 16h-7.5A1.75 1.75 0 0 1 0 14.25Z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0 1 14.25 11h-7.5A1.75 1.75 0 0 1 5 9.25Zm1.75-.25a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-7.5a.25.25 0 0 0-.25-.25Z"/></svg>
      )}
    </button>
  );
}

// ─── Integration card ─────────────────────────────────────────────────────────

type IntegrationCardProps = {
  name: string;
  library: string;
  lang: string;
  flow: 'oidc';
  url?: string | null;
  debugUrls?: Record<string, string>;
  onClick?: () => void;
  children?: React.ReactNode;
};

function IntegrationCard({
  name, library, lang, flow, url, debugUrls, onClick, children,
}: IntegrationCardProps) {
  const [showDebug, setShowDebug] = useState(false);

  const handleClick = () => {
    if (onClick) { onClick(); return; }
    if (url) window.location.href = url;
  };

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 hover:border-zinc-700 hover:bg-zinc-800/60 transition-colors">
      <div
        className={`flex items-start justify-between gap-3 px-5 py-4 ${!children ? 'cursor-pointer' : ''}`}
        onClick={!children ? handleClick : undefined}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="font-medium text-zinc-50 text-sm">{name}</span>
            <LangBadge lang={lang} />
            <FlowBadge flow={flow} />
          </div>
          <p className="text-xs text-zinc-500 font-mono">{library}</p>
        </div>
        <div className="flex items-center gap-1.5 shrink-0 mt-0.5">
          {debugUrls && (
            <button
              onClick={(e) => { e.stopPropagation(); setShowDebug(v => !v); }}
              className="rounded-md px-1.5 py-0.5 text-[10px] text-zinc-600 hover:text-zinc-400 hover:bg-zinc-800 transition-colors"
            >
              {showDebug ? '▲ urls' : '▼ urls'}
            </button>
          )}
          {!children && (
            <span className="text-zinc-600 text-sm">→</span>
          )}
        </div>
      </div>

      {showDebug && debugUrls && (
        <div className="border-t border-zinc-800 px-5 py-3 space-y-2">
          {Object.entries(debugUrls).map(([label, value]) => (
            <div key={label} className="text-[11px]">
              <span className="text-zinc-500">{label}</span>
              <div className="flex items-start gap-1 mt-0.5">
                <span className="font-mono text-zinc-300 break-all leading-relaxed flex-1">{value || '—'}</span>
                {value && <CopyButton value={value} />}
              </div>
            </div>
          ))}
        </div>
      )}

      {children && (
        <div className="border-t border-zinc-800 px-5 py-4">
          {children}
        </div>
      )}
    </div>
  );
}

// ─── Section header ───────────────────────────────────────────────────────────

function SectionHeader({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div className="mb-3">
      <h2 className="text-sm font-semibold text-zinc-200">{title}</h2>
      <p className="text-xs text-zinc-500 mt-0.5">{subtitle}</p>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

function SignInContent() {
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? 'http://localhost:3000';

  return (
    <main className="flex flex-1 flex-col items-center justify-center px-4 py-12">
      <div className="w-full max-w-lg">
        <h1 className="mb-8 text-center text-2xl font-semibold text-zinc-50">
          Sign in
        </h1>

        <AuthError />

        <section>
          <SectionHeader
            title="OIDC"
            subtitle="Standard redirect flow — each backend handles code exchange server-side."
          />
          <div className="flex flex-col gap-2">
            <IntegrationCard
              name="Auth.js"
              library="next-auth"
              lang="Next.js"
              flow="oidc"
              onClick={() => signIn('0account', { callbackUrl: '/profile' })}
              // Auth.js builds its callback path from the provider id, so this
              // is /api/auth/callback/0account rather than the /auth/callback
              // the hand-rolled examples use. Registering the wrong one is the
              // most common way a first integration fails.
              debugUrls={{
                'Callback URI': `${appUrl}/api/auth/callback/0account`,
                'Backchannel logout': `${appUrl}/api/auth/backchannel-logout`,
                'Sign-out URI': `${appUrl}/api/auth/signout`,
              }}
            />
            <IntegrationCard
              name="Passport.js"
              library="passport-openidconnect"
              lang="Node.js"
              flow="oidc"
              url={process.env.NEXT_PUBLIC_PASSPORT_URL
                ? `${process.env.NEXT_PUBLIC_PASSPORT_URL}/auth/login`
                : null}
              debugUrls={process.env.NEXT_PUBLIC_PASSPORT_URL ? {
                'Backend URL': process.env.NEXT_PUBLIC_PASSPORT_URL,
                'Callback URI': `${process.env.NEXT_PUBLIC_PASSPORT_URL}/auth/callback`,
                'Backchannel logout': `${process.env.NEXT_PUBLIC_PASSPORT_URL}/auth/backchannel-logout`,
              } : undefined}
            />
            <IntegrationCard
              name="openid-client"
              library="openid-client"
              lang="Node.js"
              flow="oidc"
              url={process.env.NEXT_PUBLIC_OPENID_CLIENT_URL
                ? `${process.env.NEXT_PUBLIC_OPENID_CLIENT_URL}/auth/login`
                : null}
              debugUrls={process.env.NEXT_PUBLIC_OPENID_CLIENT_URL ? {
                'Backend URL': process.env.NEXT_PUBLIC_OPENID_CLIENT_URL,
                'Callback URI': `${process.env.NEXT_PUBLIC_OPENID_CLIENT_URL}/auth/callback`,
                'Backchannel logout': `${process.env.NEXT_PUBLIC_OPENID_CLIENT_URL}/auth/backchannel-logout`,
              } : undefined}
            />
            <IntegrationCard
              name="go-oidc"
              library="coreos/go-oidc"
              lang="Go"
              flow="oidc"
              url={process.env.NEXT_PUBLIC_GO_OIDC_URL
                ? `${process.env.NEXT_PUBLIC_GO_OIDC_URL}/auth/login`
                : null}
              debugUrls={process.env.NEXT_PUBLIC_GO_OIDC_URL ? {
                'Backend URL': process.env.NEXT_PUBLIC_GO_OIDC_URL,
                'Callback URI': `${process.env.NEXT_PUBLIC_GO_OIDC_URL}/auth/callback`,
                'Backchannel logout': `${process.env.NEXT_PUBLIC_GO_OIDC_URL}/auth/backchannel-logout`,
              } : undefined}
            />
            <IntegrationCard
              name="Goth"
              library="markbates/goth"
              lang="Go"
              flow="oidc"
              url={process.env.NEXT_PUBLIC_GO_GOTH_URL
                ? `${process.env.NEXT_PUBLIC_GO_GOTH_URL}/auth/login?provider=openidConnect`
                : null}
              debugUrls={process.env.NEXT_PUBLIC_GO_GOTH_URL ? {
                'Backend URL': process.env.NEXT_PUBLIC_GO_GOTH_URL,
                'Callback URI': `${process.env.NEXT_PUBLIC_GO_GOTH_URL}/auth/callback`,
                'Backchannel logout': `${process.env.NEXT_PUBLIC_GO_GOTH_URL}/auth/backchannel-logout`,
              } : undefined}
            />
          </div>
        </section>
      </div>
    </main>
  );
}

export default function SignInPage() {
  return (
    <Suspense>
      <SignInContent />
    </Suspense>
  );
}
