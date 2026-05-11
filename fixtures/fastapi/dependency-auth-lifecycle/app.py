from datetime import datetime, timedelta, timezone

from fastapi import Cookie, Depends, FastAPI, HTTPException, Response
import jwt

app = FastAPI()
JWT_SECRET = "PLACEHOLDER_SECRET_DO_NOT_USE"
ISSUER = "https://placeholder.issuer.invalid"
AUDIENCE = "placeholder-api"


def issue_access_token(user_id: str) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    return jwt.encode(
        {
            "sub": user_id,
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": expires_at,
        },
        JWT_SECRET,
        algorithm="HS256",
    )


def current_user(session: str | None = Cookie(default=None)):
    if session is None:
        raise HTTPException(status_code=401)
    return jwt.decode(
        session,
        JWT_SECRET,
        algorithms=["HS256"],
        issuer=ISSUER,
        audience=AUDIENCE,
    )


@app.post("/login")
def login(response: Response):
    token = issue_access_token("placeholder-user")
    response.set_cookie(
        "session",
        token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=900,
    )
    return {"ok": True}


@app.post("/reset")
def reset_password():
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
    store_reset_token("placeholder-user", "PLACEHOLDER_RESET_TOKEN", expires_at)
    return {"sent": True}


@app.post("/logout")
def logout(response: Response, user=Depends(current_user)):
    revoke_session(user["sub"])
    response.delete_cookie("session")
    return Response(status_code=204)


def store_reset_token(user_id: str, token: str, expires_at: datetime):
    return {"user_id": user_id, "token": token, "expires_at": expires_at}


def revoke_session(user_id: str):
    return {"revoked": user_id}
