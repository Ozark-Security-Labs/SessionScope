export function expressCallback(req: { query: Record<string, string | undefined> }) {
  const accessToken = req.query.access_token;
  const apiKey = req.query["api_key"];
  return Boolean(accessToken && apiKey);
}

export async function GET(request: { nextUrl: URL }) {
  const searchParams = request.nextUrl.searchParams;
  const refreshToken = searchParams.get("refresh_token");
  return Response.json({ ok: Boolean(refreshToken) });
}

export function resetPassword(req: { query: Record<string, string | undefined> }) {
  const token = req.query.token;
  return consumeResetToken(token);
}

export function verifyEmail(context: { query: Record<string, string | undefined> }) {
  const token = context.query.token;
  return consumeEmailVerification(token);
}

export function dynamicTokenName(req: { query: Record<string, string | undefined> }) {
  const tokenParamName = configuredTokenParamName();
  return req.query[tokenParamName];
}

export function ignoredPagination(req: { query: Record<string, string | undefined> }) {
  return req.query.page_token || req.query.state || req.query.code;
}
