import express from "express";
import session from "express-session";

const app = express();

app.use(session({
  secret: "PLACEHOLDER_SECRET_DO_NOT_USE",
  resave: true,
  saveUninitialized: false,
  rolling: true,
  cookie: { httpOnly: true, secure: true, maxAge: 900000 },
}));

app.post("/login", (request, response) => {
  request.session.regenerate(() => {
    request.session.userId = "placeholder-user";
    response.json({ ok: true });
  });
});
