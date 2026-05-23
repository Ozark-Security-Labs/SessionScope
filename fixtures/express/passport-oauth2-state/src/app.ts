import { Strategy as OAuth2Strategy } from 'passport-oauth2'
const state = crypto.randomUUID()
new OAuth2Strategy({ authorizationURL: 'https://issuer.example/authorize', tokenURL: 'https://issuer.example/token', clientID: 'placeholder', callbackURL: 'https://app.example.com/callback', state, code_challenge: challenge }, () => {})
app.get('/callback', (req, res) => { if (req.query.state === req.session.oauthState) res.end('ok') })
