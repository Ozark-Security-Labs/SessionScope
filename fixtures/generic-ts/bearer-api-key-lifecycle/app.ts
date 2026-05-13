const API_KEY = "PLACEHOLDER_API_KEY_DO_NOT_USE";

export async function issueServiceToken(userId: string) {
  const serviceToken = generateServiceToken(userId);
  await tokenStore.create({
    data: {
      token: serviceToken,
      expiresAt: serviceTokenExpiresAt,
    },
  });
  return serviceToken;
}

export async function callPartnerApi(userId: string) {
  const serviceToken = await issueServiceToken(userId);
  return fetch("https://partner.example.test/accounts", {
    headers: {
      Authorization: `Bearer ${serviceToken}`,
      "X-API-Key": API_KEY,
    },
  });
}

export async function authorizeRequest(req: { headers: Record<string, string | undefined> }) {
  const incoming = req.headers.authorization;
  const stored = await tokenStore.findUnique({ where: { token: incoming } });
  return Boolean(stored);
}

export async function unsafeBrowserStorage() {
  localStorage.setItem("api_key", API_KEY);
}

export async function unsafeQueryTransmission(accessToken: string) {
  return fetch(`/callback?access_token=${accessToken}`);
}

export async function providerManagedToken() {
  return auth0Provider.token({ audience: "internal-api" });
}

const sampleDocumentation = "Authorization header expected";
