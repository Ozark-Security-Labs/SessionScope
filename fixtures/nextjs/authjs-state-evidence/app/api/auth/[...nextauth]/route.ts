import NextAuth from 'next-auth'
export const authOptions = { providers: [OAuthProvider({ checks: ['pkce'] })] }
export default NextAuth(authOptions)
