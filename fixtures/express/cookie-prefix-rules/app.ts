export function login(response: any, token: string) {
  response.cookie("__Host-session", token, { httpOnly: true, secure: false, sameSite: "lax", path: "/auth", domain: "example.com" });
  response.cookie("__Secure-refresh", token, { httpOnly: true, sameSite: "strict", maxAge: 900 });
  response.cookie("chips", token, { httpOnly: true, secure: true, sameSite: "none", partitioned: true });
  response.cookie("prefs", token, { httpOnly: true, secure: true, sameSite: "lax", domain: ".example.com" });
}
