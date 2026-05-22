class jwt:
    @staticmethod
    def decode(*args, **kwargs):
        return {"header": {"kid": "placeholder-key-id"}}


trusted_key_map = {"placeholder-key-id": "PLACEHOLDER_PUBLIC_KEY_DO_NOT_USE"}
ISSUER = "https://placeholder.issuer.invalid"
AUDIENCE = "placeholder-service"


def verify_access_jwt(token):
    decoded = jwt.decode(
        token,
        key=trusted_key_map,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=AUDIENCE,
        leeway=60,
        options={"complete": True, "verify_nbf": True},
    )
    return trusted_key_map.get(decoded["header"]["kid"])
