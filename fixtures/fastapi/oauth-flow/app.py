from authlib import OAuth2Session
from fastapi import FastAPI, Request

app = FastAPI()
router = app.router


@router.get("/auth")
def authorize():
    client = OAuth2Session("client-id")
    return client.create_authorization_url("https://issuer.example/authorize", response_type="code", state="STATIC_STATE_PLACEHOLDER", code_challenge="PLACEHOLDER_CODE_CHALLENGE")


@router.get("/callback")
def callback(request: Request):
    # State is read back from the query string but never compared to a stored value.
    return request.query_params.get("state")
