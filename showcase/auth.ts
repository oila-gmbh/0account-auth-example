import NextAuth from 'next-auth';
import { describe, record } from '@/app/lib/debugLog';

/**
 * Reads the claims out of a JWT without verifying it.
 *
 * Safe here and only here: this is our own ID token, handed to us over TLS by
 * the token endpoint in exchange for a code we generated. Never do this to a
 * token that arrived from somewhere else — see the back-channel logout route,
 * which verifies the signature before believing a word of it.
 */
function readClaims(jwt: string | undefined): Record<string, unknown> {
  if (!jwt) return {};
  const payload = jwt.split('.')[1];
  if (!payload) return {};
  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString());
  } catch {
    return {};
  }
}

async function refreshAccessToken(token: Record<string, unknown>) {
  const response = await fetch('https://v1.0account.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: token.refreshToken as string,
      client_id: process.env.ZERO_CLIENT_ID!,
      client_secret: process.env.ZERO_CLIENT_SECRET!,
    }),
  });
  const tokens = await response.json();
  if (!response.ok) throw tokens;
  return {
    ...token,
    accessToken: tokens.access_token as string,
    expiresAt: Math.floor(Date.now() / 1000) + (tokens.expires_in as number),
    // Use the new refresh token if the server rotated it
    refreshToken: (tokens.refresh_token as string) ?? token.refreshToken,
    // Keep the newest ID token: it is the id_token_hint that logout needs, and
    // the old one names a session that refreshing has moved on from.
    idToken: (tokens.id_token as string) ?? token.idToken,
  };
}

export const { handlers, signIn, signOut, auth } = NextAuth({
  // Required anywhere that is not Vercel. Auth.js will not build callback URLs
  // from a host it has not been told to trust, and refuses the request with a
  // bare "Configuration" error that says nothing about the cause.
  trustHost: true,
  providers: [
    {
      id: '0account',
      name: '0account',
      type: 'oidc',
      issuer: 'https://v1.0account.com',
      clientId: process.env.ZERO_CLIENT_ID,
      clientSecret: process.env.ZERO_CLIENT_SECRET,
      // 0account requires credentials in the POST body, not Basic auth header
      client: { token_endpoint_auth_method: 'client_secret_post' },
      // offline_access requests a refresh token
      authorization: {
        params: { scope: 'openid profile email offline_access' },
      },
      // Auth.js's default mapping reads `name`, which we do not send — userinfo
      // returns given_name and family_name separately — so without this the
      // profile has no name at all.
      //
      // `id` is set to satisfy the type, but it does not survive: Auth.js v5
      // overwrites it with crypto.randomUUID() immediately after this returns,
      // so the real subject is carried through the jwt callback instead.
      profile(profile) {
        return {
          id: profile.sub,
          name: [profile.given_name, profile.family_name].filter(Boolean).join(' ') || null,
          email: profile.email,
          image: profile.picture,
        };
      },
    },
  ],
  events: {
    async signIn(message) {
      record('info', 'signin', `sub=${message.profile?.sub ?? 'unknown'}`);
    },
    async signOut(message) {
      // RP-initiated logout, server to server: end the session at 0account
      // without sending the browser anywhere. Without this the user leaves this
      // site but stays signed in there, and their phone still lists the session.
      if (!('token' in message) || !message.token?.idToken) {
        record('error', 'logout-skipped', 'no ID token on the session, so 0account was never told');
        return;
      }
      try {
        const response = await fetch('https://v1.0account.com/oauth/logout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ id_token_hint: message.token.idToken as string }),
        });
        if (!response.ok) {
          // The failure that used to be swallowed by .catch(() => {}). A 400
          // here means the local cookie is gone but the 0account session is
          // not, and the only visible symptom is the session still listed on
          // the phone — which reads as "logout does not work" with no clue why.
          const body = (await response.text()).slice(0, 300);
          record('error', 'logout-rejected', `POST /oauth/logout → ${response.status} ${body}`);
          return;
        }
        record('info', 'logout-accepted', 'POST /oauth/logout → 200, session ended at 0account');
      } catch (err) {
        record('error', 'logout-failed', describe(err));
      }
    },
  },
  callbacks: {
    async jwt({ token, account, profile }) {
      // Persist tokens from the initial sign-in
      if (account) {
        // sid names this one sign-in, and is what an arriving back-channel
        // logout token identifies. It is an ID token claim only — userinfo does
        // not carry it — so it is read here or it is lost.
        const sid = readClaims(account.id_token)['sid'];
        if (!sid) {
          record(
            'error',
            'missing-sid',
            'the ID token carried no sid claim, so a logout from the phone cannot be matched to this session',
          );
        }
        return {
          ...token,
          // The real subject. Auth.js replaces user.id with a random UUID
          // before this point, so profile.sub is the only place it survives —
          // and it is what /userinfo, logout tokens and every other example
          // identify this person by.
          zeroSub: profile?.sub ?? token.zeroSub,
          zeroSid: sid ?? token.zeroSid,
          accessToken: account.access_token,
          idToken: account.id_token,
          expiresAt: account.expires_at,
          refreshToken: account.refresh_token,
        };
      }
      // Return token if it has not expired yet
      if (Date.now() < (token.expiresAt as number) * 1000 - 60_000)
        return token;
      // Refresh the access token
      try {
        return await refreshAccessToken(token);
      } catch (err) {
        record('error', 'refresh-failed', describe(err));
        return { ...token, error: 'RefreshAccessTokenError' };
      }
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken as string;
      // zeroSub, not token.sub: the latter is Auth.js's own generated id.
      if (token.zeroSub) session.user.id = token.zeroSub as string;
      if (token.zeroSid) session.sid = token.zeroSid as string;
      if (token.error) session.error = token.error as string;
      return session;
    },
  },
});
