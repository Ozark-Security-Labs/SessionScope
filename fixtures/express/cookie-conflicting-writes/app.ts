export function login(response: any, token: string) {
  response.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax" });
  response.cookie("session", token, { httpOnly: true, secure: false, sameSite: "none" });
  response.cookie("csrf", token, { httpOnly: true, secure: true, sameSite: "strict" });
}
export function refresh(response: any, token: string) {
  response.cookie("session", token, { httpOnly: true, secure: true, sameSite: "strict" });
}
