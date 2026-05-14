import express from "express";
import session from "express-session";
import cookieSession from "cookie-session";
import jwt from "jsonwebtoken";

const app = express();
const secret = "PLACEHOLDER_SECRET_DO_NOT_USE";

app.use(
  session({
    name: "sid",
    secret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 900000,
    },
  }),
);

app.use(
  cookieSession({
    name: "session",
    keys: [secret],
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  }),
);

app.post("/login", (request, response) => {
  request.session.regenerate(() => {
    request.session.userId = "placeholder-user";
    const accessJwt = jwt.sign(
      { sub: "placeholder-user", iss: "https://placeholder.issuer.invalid", aud: "placeholder-web" },
      secret,
      { expiresIn: "15m", algorithm: "HS256" },
    );
    response.cookie("access", accessJwt, { httpOnly: true, secure: true, sameSite: "lax" });
    response.json({ ok: true });
  });
});

app.post("/refresh", (request, response) => {
  const previousRefreshToken = request.cookies.refresh_token;
  validateRefreshToken(previousRefreshToken);
  revokeRefreshToken(previousRefreshToken);
  response.cookie("refresh_token", "PLACEHOLDER_RESET_TOKEN_ROTATED", {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 900000,
  });
});

app.post("/logout", (request, response) => {
  revokeRefreshToken(request.cookies.refresh_token);
  request.session.destroy(() => {
    response.clearCookie("sid");
    response.clearCookie("refresh_token");
    response.sendStatus(204);
  });
});

function validateRefreshToken(_token: string) {
  return true;
}

function revokeRefreshToken(_token: string) {
  return true;
}
