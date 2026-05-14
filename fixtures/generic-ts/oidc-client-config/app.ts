import { Issuer } from "openid-client";

export async function buildOidcClient() {
  const issuer = await Issuer.discover("https://issuer.example.invalid/");
  const oidcClient = new issuer.Client({
    client_id: process.env.OIDC_CLIENT_ID,
    redirect_uris: ["https://app.example.invalid/auth/callback"],
    response_types: ["code"],
    audience: "orders-api",
    scope: "openid profile offline_access orders:read",
  });
  return oidcClient;
}

export async function handleCallback(params: URLSearchParams) {
  const oidcClient = await buildOidcClient();
  const tokenSet = await oidcClient.callback("https://app.example.invalid/auth/callback", params, {
    issuer: "https://issuer.example.invalid/",
    audience: "orders-api",
  });
  if (tokenSet.refresh_token) {
    await oidcClient.refresh(tokenSet.refresh_token);
    await oidcClient.revoke(tokenSet.refresh_token, "refresh_token");
  }
  return tokenSet;
}
