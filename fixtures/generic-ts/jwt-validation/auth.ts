import jwt from "jsonwebtoken";

const JWT_SECRET = "PLACEHOLDER_SECRET_DO_NOT_USE";
const ISSUER = "https://placeholder.issuer.invalid";
const AUDIENCE = "placeholder-service";

export function issueAccessJwt(userId: string): string {
  return jwt.sign(
    {
      sub: userId,
      scope: "read:sessions",
    },
    JWT_SECRET,
    {
      issuer: ISSUER,
      audience: AUDIENCE,
      expiresIn: "15m",
    },
  );
}

export function verifyAccessJwt(token: string) {
  return jwt.verify(token, JWT_SECRET, {
    issuer: ISSUER,
    audience: AUDIENCE,
  });
}

export function verifyLegacyJwt(token: string) {
  return jwt.verify(token, JWT_SECRET, { ignoreExpiration: true });
}

export function inspectAccessJwt(token: string) {
  return jwt.decode(token);
}

export const placeholderJwt =
  "PLACEHOLDER_HEADER.PLACEHOLDER_PAYLOAD.PLACEHOLDER_SIGNATURE";
