import NextAuth from "next-auth";
import Auth0Provider from "next-auth/providers/auth0";

export const authOptions = {
  providers: [
    Auth0Provider({
      issuer: process.env.AUTH0_ISSUER,
      clientId: process.env.AUTH0_CLIENT_ID,
      authorization: {
        params: {
          audience: "orders-api",
          scope: "openid profile offline_access",
        },
      },
    }),
  ],
  session: { strategy: "jwt" },
  callbacks: {
    async jwt({ token, account }) {
      if (account?.refresh_token) {
        token.refreshToken = account.refresh_token;
      }
      if (token.refreshToken) {
        return refreshAuth0AccessToken(token.refreshToken);
      }
      return token;
    },
    async session({ session, token }) {
      session.provider = "auth0";
      session.accessToken = token.accessToken;
      return session;
    },
  },
};

async function refreshAuth0AccessToken(refreshToken: string) {
  return auth0Provider.refresh(refreshToken);
}

export const GET = NextAuth(authOptions);
export const POST = NextAuth(authOptions);

export async function DELETE() {
  await auth0Provider.revoke("PLACEHOLDER_RESET_TOKEN");
}
