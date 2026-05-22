import { cookies } from "next/headers";

export async function POST() {
  cookies().set("session", "PLACEHOLDER_RESET_TOKEN", { httpOnly: true, secure: true, sameSite: "lax" });
  cookies().set("session", "PLACEHOLDER_RESET_TOKEN", { httpOnly: true, secure: false, sameSite: "none" });
  cookies().set("csrf", "PLACEHOLDER_RESET_TOKEN", { httpOnly: true, secure: true, sameSite: "strict" });
  return Response.json({ ok: true });
}
