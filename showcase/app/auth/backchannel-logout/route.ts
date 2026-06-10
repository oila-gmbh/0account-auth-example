// Re-export the handler so /auth/backchannel-logout works alongside
// /api/auth/backchannel-logout — consistent with all other backends.
export { POST } from "@/app/api/auth/backchannel-logout/route"
