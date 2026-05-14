import { NextRequest, NextResponse } from "next/server";
import { jwtVerify, SignJWT } from "jose";

const issuer = "https://placeholder.issuer.invalid";
const audience = "placeholder-web";
const secret = new TextEncoder().encode("PLACEHOLDER_SECRET_DO_NOT_USE");

export async function POST() {
  const sessionJwt = await new SignJWT({ sub: "placeholder-user" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setExpirationTime("15m")
    .sign(secret);

  const response = NextResponse.json({ ok: true });
  response.cookies.set("session", sessionJwt, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
  });
  return response;
}

export async function GET(request: NextRequest) {
  const token = request.headers.get("authorization")?.replace("Bearer ", "");
  if (!token) {
    return NextResponse.json({ ok: false }, { status: 401 });
  }

  await jwtVerify(token, secret, { issuer, audience });
  return NextResponse.json({ ok: true });
}

export async function PATCH(request: NextRequest) {
  const refreshToken = request.cookies.get("refresh_token")?.value;
  await validateRefreshToken(refreshToken);
  await revokeRefreshToken(refreshToken);
  const rotatedRefreshToken = "PLACEHOLDER_RESET_TOKEN_ROTATED";
  const response = NextResponse.json({ refreshed: true });
  response.cookies.set("refresh_token", rotatedRefreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 900,
  });
  return response;
}

export async function DELETE() {
  await destroyServerSession("placeholder-session-id");
  const response = new NextResponse(null, { status: 204 });
  response.cookies.delete("session");
  response.cookies.delete("refresh_token");
  return response;
}

async function validateRefreshToken(_token: string | undefined) {
  return true;
}

async function revokeRefreshToken(_token: string | undefined) {
  return true;
}

async function destroyServerSession(_sessionId: string) {
  return true;
}
