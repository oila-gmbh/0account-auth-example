import NextAuth from 'next-auth';

async function refreshAccessToken(token: Record<string, unknown>) {
  const response = await fetch('https://v1.0account.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: token.refreshToken as string,
      client_id: process.env.NEXT_PUBLIC_CLIENT_ID!,
      client_secret: process.env.CLIENT_SECRET!,
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
  };
}

const env = process.env;
for (const key in env) {
  console.log(`${key}: ${env[key]}`);
}

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    {
      id: '0account',
      name: '0account',
      type: 'oidc',
      issuer: 'https://v1.0account.com',
      clientId: process.env.NEXT_PUBLIC_CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      // 0account requires credentials in the POST body, not Basic auth header
      client: { token_endpoint_auth_method: 'client_secret_post' },
      // offline_access requests a refresh token
      authorization: {
        params: { scope: 'openid profile email offline_access' },
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
    async jwt({ token, account }) {
      // Persist tokens from the initial sign-in
      if (account) {
        return {
          ...token,
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
      if (token.sub) session.user.id = token.sub;
      if (token.error) session.error = token.error as string;
      return session;
    },
  },
});
