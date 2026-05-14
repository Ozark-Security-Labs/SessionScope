from datetime import datetime, timedelta, timezone

from fastapi import Cookie, Depends, FastAPI, HTTPException, Response, Security
from fastapi.security import APIKeyCookie, OAuth2PasswordBearer
import jwt

app = FastAPI()
JWT_SECRET = "PLACEHOLDER_SECRET_DO_NOT_USE"
ISSUER = "https://placeholder.issuer.invalid"
AUDIENCE = "placeholder-api"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
session_cookie = APIKeyCookie(name="session")


def issue_access_token(user_id: str) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    return jwt.encode(
        {"sub": user_id, "iss": ISSUER, "aud": AUDIENCE, "exp": expires_at},
        JWT_SECRET,
        algorithm="HS256",
    )


def current_user(
    bearer_token: str = Security(oauth2_scheme),
    session: str | None = Cookie(default=None),
):
    token = session or bearer_token
    if token is None:
        raise HTTPException(status_code=401)
    return jwt.decode(
        token,
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


@app.post("/refresh")
def refresh(response: Response, user=Depends(current_user)):
    previous_refresh_token = "PLACEHOLDER_RESET_TOKEN"
    validate_refresh_token(previous_refresh_token)
    revoke_refresh_token(previous_refresh_token)
    response.set_cookie(
        "refresh_token",
        "PLACEHOLDER_RESET_TOKEN_ROTATED",
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=900,
    )
    return {"refreshed": user["sub"]}


@app.post("/logout")
def logout(response: Response, user=Depends(current_user), api_key: str = Security(session_cookie)):
    revoke_session(user["sub"])
    revoke_refresh_token(api_key)
    response.delete_cookie("session")
    response.delete_cookie("refresh_token")
    return Response(status_code=204)


def validate_refresh_token(token: str):
    return {"token": token, "expires_at": datetime.now(timezone.utc) + timedelta(minutes=15)}


def revoke_refresh_token(token: str):
    return {"revoked": token}


def revoke_session(user_id: str):
    return {"revoked": user_id}
