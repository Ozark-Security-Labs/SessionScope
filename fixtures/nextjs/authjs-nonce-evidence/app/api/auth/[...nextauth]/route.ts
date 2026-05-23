import NextAuth from 'next-auth'
export const authOptions = { providers: [OIDCProvider({ checks: ['pkce', 'state'] })] }
export default NextAuth(authOptions)
