export async function forwardInboundAuthorization(request: {
  headers: { authorization?: string };
}) {
  const authorization = request.headers.authorization;
  return fetch("https://orders.example.invalid/api/orders", {
    headers: { Authorization: authorization },
  });
}

export async function callOrdersWithServiceToken() {
  const serviceToken = process.env.ORDERS_TOKEN;
  return fetch("https://orders.example.invalid/api/orders", {
    headers: {
      "X-Service-Token": serviceToken,
      audience: "orders_api",
    },
  });
}

export async function providerManagedToken(provider: {
  token(input: { token: string }): Promise<string>;
}) {
  return provider.token({ token: "PLACEHOLDER_RESET_TOKEN" });
}
