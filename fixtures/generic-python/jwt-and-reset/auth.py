from datetime import datetime, timedelta, timezone

import jwt

JWT_SECRET = "PLACEHOLDER_SECRET_DO_NOT_USE"
ISSUER = "https://placeholder.issuer.invalid"
AUDIENCE = "placeholder-python-service"
PLACEHOLDER_JWT = "PLACEHOLDER_HEADER.PLACEHOLDER_PAYLOAD.PLACEHOLDER_SIGNATURE"


def issue_access_jwt(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": user_id,
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + timedelta(minutes=15),
        },
        JWT_SECRET,
        algorithm="HS256",
    )


def verify_access_jwt(token: str):
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=["HS256"],
        issuer=ISSUER,
        audience=AUDIENCE,
    )


def verify_legacy_jwt(token: str):
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])


def create_reset_token(user_id: str):
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
    return {
        "user_id": user_id,
        "token": "PLACEHOLDER_RESET_TOKEN",
        "expires_at": expires_at,
        "single_use": True,
    }
