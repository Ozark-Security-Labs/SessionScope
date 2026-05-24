from authlib import OAuth2Session
def login():
    client = OAuth2Session('client-id')
    return client.create_authorization_url('https://issuer.example/authorize', response_type='code', scope='openid profile', state=secrets.token_urlsafe(32), nonce=secrets.token_urlsafe(32), code_challenge='PLACEHOLDER_CODE_CHALLENGE')
def verify(id_token):
    return client.parse_id_token(id_token, nonce=expected_nonce)
