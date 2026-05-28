// Auth0 SDK token lifecycle: client-credentials issue, refresh, and logout.
export async function auth0ClientCredentials() {
  return auth0.clientCredentialsToken({
    audience: "orders-api",
    scope: "orders:read",
  });
}

export async function auth0Refresh() {
  return auth0.oauth.refreshToken({
    refresh_token: "PLACEHOLDER_RESET_TOKEN",
    scope: "offline_access",
  });
}

export async function auth0Logout() {
  return auth0.logout({ returnTo: "https://app.example.com/" });
}
