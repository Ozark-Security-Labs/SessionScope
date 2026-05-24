import express from "express";
import session from "express-session";

const app = express();

app.use(session({
  secret: "PLACEHOLDER_SECRET_DO_NOT_USE",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, maxAge: 900000 },
}));

app.get("/account", (_request, response) => {
  response.json({ ok: true });
});
