import express from "express";

const app = express();

async function issueRefreshToken(userId: string) {
  return refreshTokens.create({ userId, expiresAt: Date.now() + 86400 });
}

async function revokeRefreshFamily(userId: string) {
  await refreshTokens.deleteMany({ user_id: userId });
}

app.post("/refresh", async (request, response) => {
  const refreshToken = request.cookies.refresh_token;
  const nextToken = await issueRefreshToken(request.user.id);
  response.cookie("refresh_token", nextToken, { httpOnly: true, maxAge: 86400 });
});

app.post("/logout", async (request, response) => {
  await revokeRefreshFamily(request.user.id);
  response.clearCookie("refresh_token");
  response.status(204).end();
});
