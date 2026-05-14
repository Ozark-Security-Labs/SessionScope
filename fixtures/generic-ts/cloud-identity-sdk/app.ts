export async function cloudIdentityFlow() {
  const auth0Token = await auth0.clientCredentialsToken({
    audience: "orders-api",
    scope: "orders:read",
  });
  await okta.oauth2.refreshToken("PLACEHOLDER_RESET_TOKEN", {
    issuer: process.env.OKTA_ISSUER,
    scopes: ["openid", "offline_access"],
  });
  await cognito.revokeToken({
    Token: "PLACEHOLDER_RESET_TOKEN",
    ClientId: process.env.COGNITO_CLIENT_ID,
  });
  await supabase.auth.signOut();
  await clerk.sessions.revoke("PLACEHOLDER_RESET_TOKEN");
  return auth0Token;
}
