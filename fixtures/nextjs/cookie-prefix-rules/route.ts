import { cookies } from "next/headers";
import { NextResponse } from "next/server";

export async function POST() {
  cookies().set("__Host-session", "PLACEHOLDER_RESET_TOKEN", { httpOnly: true, secure: false, sameSite: "lax", path: "/auth", domain: "example.com" });
  const response = NextResponse.json({ ok: true });
  response.cookies.set("__Secure-refresh", "PLACEHOLDER_RESET_TOKEN", { httpOnly: true, sameSite: "strict" });
  response.cookies.set("chips", "PLACEHOLDER_RESET_TOKEN", { httpOnly: true, secure: true, sameSite: "none", partitioned: true });
  return response;
}
