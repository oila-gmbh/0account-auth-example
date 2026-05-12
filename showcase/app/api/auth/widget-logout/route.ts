import type { NextRequest } from "next/server"
import { NextResponse } from "next/server"
import { cookies } from "next/headers"

// Clears the widget session and calls 0account's server-to-server logout endpoint.
export async function GET(req: NextRequest) {
  const cookieStore = await cookies()
  const raw = cookieStore.get("widget_session")?.value

  let idToken: string | undefined
  if (raw) {
    try {
      const session = JSON.parse(raw) as { idToken?: string }
      idToken = session.idToken
    } catch {
      // malformed cookie — ignore
    }
  }

  if (idToken) {
    // Server-to-server: terminate the session on 0account's side without a browser redirect.
    await fetch("https://v1.0account.com/oauth/logout", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ id_token_hint: idToken }),
    }).catch(() => {})
  }

  const origin = req.nextUrl.origin
  const response = NextResponse.redirect(new URL("/", origin))
  response.cookies.set("widget_session", "", { maxAge: 0, path: "/" })
  return response
}
