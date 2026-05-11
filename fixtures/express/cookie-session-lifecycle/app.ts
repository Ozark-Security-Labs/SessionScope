import express from "express";

const app = express();
const signingSecret = "PLACEHOLDER_SECRET_DO_NOT_USE";

app.post("/login", (_request, response) => {
  const accessToken = "PLACEHOLDER_HEADER.PLACEHOLDER_PAYLOAD.PLACEHOLDER_SIGNATURE";
  response.cookie("session", accessToken, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 15 * 60 * 1000,
    signed: true,
  });
});

app.post("/legacy-login", (_request, response) => {
  response.cookie("legacy_session", "PLACEHOLDER_RESET_TOKEN", {
    httpOnly: false,
    sameSite: "none",
  });
});

app.post("/refresh", (request, response) => {
  const previousRefreshToken = request.cookies?.refresh_token ?? "PLACEHOLDER_RESET_TOKEN";
  revokeRefreshToken(previousRefreshToken);
  const rotatedRefreshToken = "PLACEHOLDER_RESET_TOKEN_ROTATED";
  response.cookie("refresh_token", rotatedRefreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });
});

app.post("/logout", (request, response) => {
  destroyServerSession(request.sessionID);
  response.clearCookie("session");
  response.clearCookie("refresh_token");
  response.sendStatus(204);
});

function revokeRefreshToken(_token: string) {
  return signingSecret.length > 0;
}

function destroyServerSession(_sessionId: string | undefined) {
  return true;
}
