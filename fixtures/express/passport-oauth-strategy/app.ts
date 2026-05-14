import express from "express";
import passport from "passport";
import { Strategy as OAuth2Strategy } from "passport-oauth2";

const app = express();

passport.use(
  "oauth-provider",
  new OAuth2Strategy(
    {
      authorizationURL: "https://issuer.example.invalid/oauth/authorize",
      tokenURL: "https://issuer.example.invalid/oauth/token",
      clientID: process.env.OAUTH_CLIENT_ID,
      callbackURL: "/auth/provider/callback",
      scope: ["openid", "profile", "orders:read"],
      audience: "orders-api",
      issuer: "https://issuer.example.invalid/",
    },
    async (accessToken, refreshToken, profile, done) => {
      await storeProviderSession({ accessToken, refreshToken, profile });
      return done(null, profile);
    },
  ),
);

app.get("/auth/provider", passport.authenticate("oauth-provider"));
app.get(
  "/auth/provider/callback",
  passport.authenticate("oauth-provider"),
  async (req, res) => {
    await refreshProviderToken(req.user?.refreshToken);
    res.redirect("/dashboard");
  },
);

app.post("/logout", async (req, res) => {
  await oauthProvider.revoke(req.user?.refreshToken);
  req.logout(() => res.redirect("/"));
});
