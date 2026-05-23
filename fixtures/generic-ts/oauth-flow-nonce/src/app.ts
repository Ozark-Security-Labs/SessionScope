export function login(client: any) {
  return client.authorizationUrl({ response_type: 'code', scope: 'openid profile', code_challenge: challenge, state: crypto.randomUUID(), redirect_uris: ['https://app.example.com/auth/callback'] });
}
export function callback(req: any, session: any) {
  if (req.query.state === session.oauthState) return true;
}
