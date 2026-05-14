/**
 * In-memory set of revoked subject identifiers.
 *
 * Populated when 0account calls POST /api/auth/backchannel-logout with a
 * signed logout token. Server components and route handlers import this same
 * module instance so they share the same Set within a single Node.js process.
 *
 * Limitation: this is not shared across multiple server instances (e.g. in
 * a horizontally-scaled deployment). Use Redis or a database in production.
 */
export const revokedSubs = new Set<string>()
