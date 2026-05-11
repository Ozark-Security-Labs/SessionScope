import { cookies } from "next/headers";
import { jwtVerify, SignJWT } from "jose";

const issuer = "https://placeholder.issuer.invalid";
const audience = "placeholder-web";
const secret = new TextEncoder().encode("PLACEHOLDER_SECRET_DO_NOT_USE");

export async function POST() {
  const accessJwt = await new SignJWT({ sub: "placeholder-user" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setExpirationTime("15m")
    .sign(secret);

  cookies().set("access", accessJwt, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  });

  return Response.json({ ok: true });
}

export async function GET(request: Request) {
  const token = request.headers.get("authorization")?.replace("Bearer ", "");
  if (!token) {
    return new Response("missing", { status: 401 });
  }

  await jwtVerify(token, secret, {
    issuer,
    audience,
  });

  return Response.json({ ok: true });
}

export async function PATCH() {
  cookies().set("refresh", "PLACEHOLDER_RESET_TOKEN_ROTATED", {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });
  return Response.json({ refreshed: true });
}

export async function DELETE() {
  cookies().delete("access");
  cookies().delete("refresh");
  return new Response(null, { status: 204 });
}
