// @ts-nocheck
import { jwtVerify } from "jose";

const trustedJwksKeyMap = "PLACEHOLDER_PUBLIC_KEY_DO_NOT_USE";
const ISSUER = "https://placeholder.issuer.invalid";
const AUDIENCE = "placeholder-service";

export async function verifyAccessJwt(token: string) {
  const result = await jwtVerify(token, trustedJwksKeyMap, {
    algorithms: ["RS256"],
    issuer: ISSUER,
    audience: AUDIENCE,
    complete: true,
    ignoreNotBefore: false,
  });
  return trustedJwksKeyMap && result.protectedHeader.jku;
}
