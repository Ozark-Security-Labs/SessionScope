export function login(client: any) {
  return client.authorizationUrl({ response_type: 'code', scope: 'profile', state: crypto.randomUUID(), redirect_uris: ['https://app.example.com/auth/callback'] });
}
export function callback(req: any, session: any) {
  if (req.query.state === session.oauthState) return true;
}
