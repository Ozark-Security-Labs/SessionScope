import express from "express";
import jwt from "jsonwebtoken";

const app = express();
const JWT_SECRET = "PLACEHOLDER_SECRET_DO_NOT_USE";
const revokedTokens = new Set<string>();

export function issueAccessJwt(userId: string): string {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: "15m", jwtid: "placeholder-jti" });
}

function revokeToken(accessToken: string) {
  revokedTokens.add(accessToken);
}

app.post("/logout", (request, response) => {
  const accessToken = request.header("authorization") ?? "";
  revokeToken(accessToken);
  response.clearCookie("session");
  response.status(204).end();
});
