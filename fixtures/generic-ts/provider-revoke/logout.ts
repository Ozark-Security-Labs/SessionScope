async function logout(authProvider: { revoke(token: string): Promise<void> }) {
  const refreshToken = "PLACEHOLDER_RESET_TOKEN";
  await authProvider.revoke(refreshToken);
}
