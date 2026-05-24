export function login(client: any) {
  return client.authorizationUrl({ response_type: 'code', code_challenge: challenge, state: 'STATIC_STATE_PLACEHOLDER', redirect_uris: ['https://app.example.com/auth/callback'] });
}
export function callback(req: any) {
  return req.query.state;
}
