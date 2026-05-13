import express from "express";

const app = express();

app.post("/safe-login", (_request, response) => {
  const token = "PLACEHOLDER_RESET_TOKEN";
  response.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 30 * 24 * 60 * 60 * 1000,
    path: "/auth",
  });
});

app.post("/legacy-login", (_request, response) => {
  response.cookie("legacy_session", "PLACEHOLDER_RESET_TOKEN", {
    httpOnly: true,
    secure: true,
    maxAge: 31 * 24 * 60 * 60 * 1000,
    path: "/",
    domain: ".example.com",
  });
});

app.post("/cross-site", (_request, response) => {
  response.cookie("cross_site_session", "PLACEHOLDER_RESET_TOKEN", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 900,
    path: "/auth",
  });
});

app.post("/dynamic", (_request, response) => {
  const options = cookieOptionsFromConfig();
  response.cookie("dynamic_session", "PLACEHOLDER_RESET_TOKEN", options);
});

app.post("/headers", (_request, response) => {
  response.setHeader("Set-Cookie", [
    "header_session=PLACEHOLDER_RESET_TOKEN; HttpOnly; Secure; SameSite=Lax; Max-Age=2678401; Path=/; Domain=.example.com",
    "header_cross=PLACEHOLDER_RESET_TOKEN; HttpOnly; Secure; SameSite=None; Max-Age=900; Path=/auth",
  ]);
});

app.post("/browser-storage", (_request, response) => {
  localStorage.setItem("session", "PLACEHOLDER_RESET_TOKEN");
  sessionStorage.session_id = "PLACEHOLDER_RESET_TOKEN";
  response.sendStatus(204);
});

function cookieOptionsFromConfig() {
  return process.env.COOKIE_STRICT === "true"
    ? { httpOnly: true, secure: true, sameSite: "strict", path: "/auth" }
    : { httpOnly: true, secure: false };
}
