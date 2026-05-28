import express from "express";
import jwt from "jsonwebtoken";

const app = express();
// Signing key is read from the environment rather than a literal so the fixture
// focuses on JWT validation posture, not secret hygiene.
const JWT_SECRET = process.env.JWT_SIGNING_SECRET ?? "";
const ISSUER = "https://placeholder.issuer.invalid";
const AUDIENCE = "placeholder-service";

export function issueAccessJwt(userId: string): string {
  const claims = {
    sub: userId,
    tenant_id: "placeholder-tenant",
    roles: ["admin"],
    scope: "read:sessions",
  };
  return jwt.sign(claims, JWT_SECRET, {
    issuer: ISSUER,
    audience: AUDIENCE,
    expiresIn: "15m",
  });
}

app.post("/sign", (req, res) => {
  const token = issueAccessJwt(req.body.userId);
  res.json({ token });
});

// Verifies with issuer and audience pinned — the safe baseline path.
app.get("/protected", (req, res) => {
  const header = req.headers.authorization;
  const token = header && header.split(" ")[1];
  if (!token) return res.sendStatus(401);
  const payload = jwt.verify(token, JWT_SECRET, {
    issuer: ISSUER,
    audience: AUDIENCE,
  });
  res.json(payload);
});

// Legacy verify: disables expiry enforcement and pins neither issuer nor audience.
app.get("/legacy", (req, res) => {
  const header = req.headers.authorization;
  const token = header && header.split(" ")[1];
  if (!token) return res.sendStatus(401);
  const payload = jwt.verify(token, JWT_SECRET, { ignoreExpiration: true });
  res.json(payload);
});

// Decodes without verifying the signature.
app.get("/inspect", (req, res) => {
  const header = req.headers.authorization;
  const token = header && header.split(" ")[1];
  if (!token) return res.sendStatus(401);
  res.json(jwt.decode(token));
});

export const placeholderJwt =
  "PLACEHOLDER_HEADER.PLACEHOLDER_PAYLOAD.PLACEHOLDER_SIGNATURE";
