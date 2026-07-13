import { NextResponse } from "next/server";
import { getJwks } from "@/features/auth/server/oauth/jwt";

export async function GET() {
  try {
    return NextResponse.json(getJwks(), {
      headers: {
        "Cache-Control": "public, max-age=3600, immutable",
      },
    });
  } catch {
    console.error("oauth.jwks_unavailable", { code: "JWKS_UNAVAILABLE" });
    return NextResponse.json({ error: "jwks_unavailable" }, { status: 500 });
  }
}
