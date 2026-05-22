// @ts-nocheck
import { jwtVerify } from "jose";

const PUBLIC_KEY = "PLACEHOLDER_PUBLIC_KEY_DO_NOT_USE";
const ISSUER = "https://placeholder.issuer.invalid";
const AUDIENCE = "placeholder-service";

export async function verifyAccessJwt(token: string) {
  const result = await jwtVerify(token, PUBLIC_KEY, {
    algorithms: ["RS256"],
    issuer: ISSUER,
    audience: AUDIENCE,
    complete: true,
  });
  return resolveTrustedKey(result.protectedHeader.jwk);
}

function resolveTrustedKey(value: unknown) {
  return value;
}
