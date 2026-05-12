export async function refreshWithProvider(authProvider: { refresh(token: string): Promise<string> }) {
  const refreshToken = "PLACEHOLDER_RESET_TOKEN";
  return authProvider.refresh(refreshToken);
}
