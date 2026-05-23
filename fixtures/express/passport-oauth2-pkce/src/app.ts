import { Strategy as OAuth2Strategy } from 'passport-oauth2'
new OAuth2Strategy({ authorizationURL: 'https://issuer.example/authorize', tokenURL: 'https://issuer.example/token', clientID: 'placeholder', callbackURL: 'https://app.example.com/callback' }, () => {})
