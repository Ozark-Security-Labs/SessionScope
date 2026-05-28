import { cookies } from "next/headers";
// Helpers are imported (not defined here) so the fixture exercises handler-level
// transition detection without helper definitions emitting their own signals.
import { authenticateUser, elevateUserRole, loadSession } from "@/lib/auth";

// Login handler that writes the session cookie without any clear-and-reissue.
// No rotation evidence sits near the auth transition, so this handler should be
// flagged for login regeneration review.
export async function POST(request: Request) {
  const body = await request.json();
  const session = await authenticateUser(body.email, body.credential);
  cookies().set("session", session.token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });
  return Response.json({ ok: true });
}

// Login handler that performs an explicit clear-and-reissue rotation:
// cookies().delete then cookies().set at the auth transition. This emits a
// nextjs-hinted reissue signal in the same handler scope and is suppressed.
export async function PUT(request: Request) {
  const body = await request.json();
  const session = await authenticateUser(body.email, body.credential);
  cookies().delete("session");
  cookies().set("session", session.token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });
  return Response.json({ ok: true });
}

// Privilege-elevation handler that rewrites the session at a privilege change
// without rotation. This should be flagged for privilege regeneration review.
export async function PATCH(request: Request) {
  const body = await request.json();
  const session = await loadSession(body.userId);
  await elevateUserRole(body.userId);
  cookies().set("session", session.token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });
  return Response.json({ ok: true });
}

// Logout handler — deletes the session cookie. Logout context is excluded from
// session-fixation review, so no finding is expected here.
export async function DELETE() {
  cookies().delete("session");
  return new Response(null, { status: 204 });
}
