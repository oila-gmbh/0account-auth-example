import crypto from 'crypto';
import { NextRequest, NextResponse } from 'next/server';
import { revokeSession } from '@/app/lib/revokedSessions';
import { describe, record } from '@/app/lib/debugLog';

const ISSUER = 'https://v1.0account.com';
const LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

let cachedKey: crypto.KeyObject | null = null;

async function getLogoutKey(): Promise<crypto.KeyObject> {
  if (cachedKey) return cachedKey;
  const res = await fetch(`${ISSUER}/.well-known/jwks.json`, { next: { revalidate: 3600 } });
  const { keys } = (await res.json()) as { keys: Array<{ kty: string; crv: string; x: string }> };
  const key = keys.find((k) => k.kty === 'OKP' && k.crv === 'Ed25519');
  if (!key) throw new Error('no Ed25519 key in the JWKS');
  cachedKey = crypto.createPublicKey({ key: key as crypto.JsonWebKey, format: 'jwk' });
  return cachedKey;
}

type LogoutClaims = {
  iss?: string;
  aud?: string | string[];
  sub?: string;
  sid?: string;
  events?: Record<string, unknown>;
};

/**
 * Checks the token is one 0account signed, addressed to us, saying what it
 * claims to say.
 *
 * This arrived over the open internet on an unauthenticated POST, so every part
 * of it is untrusted until the signature says otherwise. Skipping any of these
 * checks means anyone who can reach this URL can sign your users out at will.
 */
async function verifyLogoutToken(raw: string): Promise<LogoutClaims> {
  const parts = raw.split('.');
  if (parts.length !== 3) throw new Error('not a JWT');

  const signed = crypto.verify(
    null,
    Buffer.from(`${parts[0]}.${parts[1]}`),
    await getLogoutKey(),
    Buffer.from(parts[2], 'base64url'),
  );
  if (!signed) throw new Error('signature does not verify against the 0account JWKS');

  const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString()) as LogoutClaims;

  if (claims.iss !== ISSUER) throw new Error(`issued by ${claims.iss}, not ${ISSUER}`);

  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audience.includes(process.env.ZERO_CLIENT_ID!)) {
    throw new Error('addressed to a different client');
  }

  if (!claims.events?.[LOGOUT_EVENT]) throw new Error('not a back-channel logout event');

  // sub says who; sid says which of their sessions ended. Acting on sub alone
  // would end every session that user has, on every device.
  if (!claims.sid) throw new Error('no sid, so there is no way to tell which session ended');

  return claims;
}

/**
 * POST /api/auth/backchannel-logout
 *
 * 0account calls this when a session ends somewhere else — most visibly when
 * the user terminates it from their phone. Register the URL as the app's
 * **backchannel logout URI**. It has to be reachable from the internet: a
 * localhost address can never receive one, which is why this only works on a
 * deployed or tunnelled host.
 */
export async function POST(req: NextRequest) {
  let raw: string | null = null;

  const contentType = req.headers.get('content-type') ?? '';
  if (contentType.includes('application/x-www-form-urlencoded')) {
    raw = (await req.formData()).get('logout_token') as string | null;
  } else {
    raw = ((await req.json().catch(() => ({}))) as { logout_token?: string }).logout_token ?? null;
  }

  if (!raw) {
    record('error', 'backchannel-logout', 'a POST arrived with no logout_token');
    return new NextResponse('missing logout_token', { status: 400 });
  }

  try {
    const claims = await verifyLogoutToken(raw);
    revokeSession(claims.sid!);
    record('info', 'backchannel-logout', `accepted for sub=${claims.sub} sid=${claims.sid}`);
    return new NextResponse(null, { status: 200 });
  } catch (err) {
    record('error', 'backchannel-logout', `rejected: ${describe(err)}`);
    return new NextResponse('invalid logout_token', { status: 400 });
  }
}
