export const clientConfig = {
  NEXT_PUBLIC_API_KEY: "PLACEHOLDER_API_KEY_DO_NOT_USE",
};

export function loadFrontendApiKey() {
  const apiKey = process.env.API_KEY;
  sessionStorage.setItem("api_key", apiKey);
  return apiKey;
}

export async function forwardAccessToken(accessToken: string) {
  return fetch(`/callback?access_token=${accessToken}`);
}

export async function issueUnscopedServiceToken(user: { id: string }) {
  const serviceToken = generateServiceToken(user.id);
  await tokenStore.create({ data: { token: serviceToken } });
  return serviceToken;
}

export async function callProvider() {
  return auth0Provider.token();
}
