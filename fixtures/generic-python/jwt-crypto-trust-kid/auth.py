class jwt:
    @staticmethod
    def decode(*args, **kwargs):
        return {"header": {"kid": "placeholder-key-id"}}


PUBLIC_KEY = "PLACEHOLDER_PUBLIC_KEY_DO_NOT_USE"
ISSUER = "https://placeholder.issuer.invalid"
AUDIENCE = "placeholder-service"


def verify_access_jwt(token):
    decoded = jwt.decode(
        token,
        key=PUBLIC_KEY,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=AUDIENCE,
        options={"complete": True, "verify_nbf": True},
    )
    return decoded["header"]["kid"]
