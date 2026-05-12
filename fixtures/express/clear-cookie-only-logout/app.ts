import express from "express";

const app = express();

app.post("/login", (_request, response) => {
  response.cookie("session", "PLACEHOLDER_RESET_TOKEN", {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  });
});

app.post("/logout", (_request, response) => {
  response.clearCookie("session");
  response.sendStatus(204);
});
