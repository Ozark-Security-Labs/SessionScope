export async function detectRefreshReuse(refreshToken: string, userId: string) {
  if (isRefreshTokenReuse(refreshToken)) {
    await revokeRefreshTokenFamily(userId);
  }
}
