import express from "express";

const app = express();

app.post("/login", async (request, response) => {
  const user = await verifyPassword(request.body.email, request.body.password);
  request.session.regenerate(() => {
    request.session.userId = user.id;
    response.json({ ok: true });
  });
});

app.post("/legacy-login", async (request, response) => {
  const user = await authenticate(request.body.email, request.body.password);
  request.session.userId = user.id;
  response.json({ ok: true });
});

app.post("/cookie-session/signin", async (request, response) => {
  const user = await authenticate(request.body.email, request.body.password);
  response.clearCookie("session");
  response.cookie("session", buildSessionCookie(user.id), {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });
});

app.post("/logout", (request, response) => {
  response.clearCookie("session");
  request.session.destroy(() => response.redirect("/"));
});

app.post("/admin/promote", async (request, response) => {
  const user = await requireAdmin(request.user);
  await grantAdminRole(user.id);
  request.session.role = "admin";
  response.json({ ok: true });
});

function verifyPassword(email: string, password: string) {
  return authenticate(email, password);
}

function authenticate(_email: string, _password: string) {
  return { id: "user-id" };
}

function buildSessionCookie(userId: string) {
  return { userId };
}

function requireAdmin(user: { id: string }) {
  return user;
}

function grantAdminRole(_userId: string) {
  return Promise.resolve();
}
