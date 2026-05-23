export function login(client: any) {
  return client.authorizationUrl({ response_type: 'code', code_challenge: challenge, state: crypto.randomUUID(), redirect_uris: ['https://example.com'] });
}
export function callback(req: any, session: any) {
  if (req.query.state === session.oauthState) return true;
}
