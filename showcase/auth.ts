import NextAuth from 'next-auth';

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
      // `id` is deliberately not set here. Auth.js v5 overwrites whatever a
      // provider returns with crypto.randomUUID(), so our subject has to be
      // carried through the jwt callback instead.
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
    async signOut(message) {
      // Server-to-server: terminate the session on 0account's side without a browser redirect.
      if ('token' in message && message.token?.idToken) {
        await fetch('https://v1.0account.com/oauth/logout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            id_token_hint: message.token.idToken as string,
          }),
        }).catch(() => {});
      }
    },
  },
  callbacks: {
    async jwt({ token, account, profile }) {
      // Persist tokens from the initial sign-in
      if (account) {
        return {
          ...token,
          // The real subject. Auth.js replaces user.id with a random UUID
          // before this point, so profile.sub is the only place it survives —
          // and it is what /userinfo, logout tokens and every other example
          // identify this person by.
          zeroSub: profile?.sub ?? token.zeroSub,
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
      } catch {
        return { ...token, error: 'RefreshAccessTokenError' };
      }
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken as string;
      // zeroSub, not token.sub: the latter is Auth.js's own generated id.
      if (token.zeroSub) session.user.id = token.zeroSub as string;
      if (token.error) session.error = token.error as string;
      return session;
    },
  },
});
