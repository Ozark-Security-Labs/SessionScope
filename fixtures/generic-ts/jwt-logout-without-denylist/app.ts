import express from "express";
import jwt from "jsonwebtoken";

const app = express();
const JWT_SECRET = "PLACEHOLDER_SECRET_DO_NOT_USE";

export function issueAccessJwt(userId: string): string {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: "15m" });
}

app.post("/logout", (_request, response) => {
  response.clearCookie("session");
  response.status(204).end();
});
