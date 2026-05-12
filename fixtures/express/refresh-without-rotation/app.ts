import express from "express";

const app = express();

app.post("/refresh", async (request, response) => {
  const refreshToken = request.cookies.refresh_token;
  const stored = await refreshTokenStore.findUnique({
    where: { token: refreshToken },
  });
  const accessToken = issueAccessJwt(stored.userId);
  response.json({ accessToken });
});

function issueAccessJwt(_userId: string) {
  return "PLACEHOLDER_HEADER.PLACEHOLDER_PAYLOAD.PLACEHOLDER_SIGNATURE";
}
