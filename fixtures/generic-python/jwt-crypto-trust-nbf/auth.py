class jwt:
    @staticmethod
    def decode(*args, **kwargs):
        return {"claims": "placeholder"}


PUBLIC_KEY = "PLACEHOLDER_PUBLIC_KEY_DO_NOT_USE"
ISSUER = "https://placeholder.issuer.invalid"
AUDIENCE = "placeholder-service"


def verify_access_jwt(token):
    return jwt.decode(
        token,
        key=PUBLIC_KEY,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=AUDIENCE,
    )
