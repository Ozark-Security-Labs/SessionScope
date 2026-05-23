import NextAuth from 'next-auth'
export const authOptions = { providers: [OAuthProvider({ checks: ['pkce', 'state'] })] }
export default NextAuth(authOptions)
