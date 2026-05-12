import express from "express";

const app = express();

app.post("/refresh", async (request, response) => {
  const previousRefreshToken = request.cookies.refresh_token;
  const stored = await refreshTokenStore.findUnique({
    where: { token: previousRefreshToken },
  });
  const nextRefreshToken = generateRefreshToken(stored.userId);
  await refreshTokenStore.update({
    where: { token: previousRefreshToken },
    data: { usedAt: new Date() },
  });
  await refreshTokenStore.create({
    data: {
      token: nextRefreshToken,
      userId: stored.userId,
      expiresAt: refreshTokenExpiry(),
    },
  });
  response.cookie("refresh_token", nextRefreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 604800000,
  });
});

function generateRefreshToken(_userId: string) {
  return "PLACEHOLDER_RESET_TOKEN_ROTATED";
}

function refreshTokenExpiry() {
  return new Date(Date.now() + 604800000);
}
