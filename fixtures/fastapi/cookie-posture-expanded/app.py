from fastapi import FastAPI, Response

app = FastAPI()


@app.post("/safe-login")
def safe_login(response: Response):
    token = "PLACEHOLDER_RESET_TOKEN"
    response.set_cookie(
        "session",
        token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=2592000,
        path="/auth",
    )


@app.post("/legacy-login")
def legacy_login(response: Response):
    response.set_cookie(
        "legacy_session",
        "PLACEHOLDER_RESET_TOKEN",
        httponly=True,
        secure=True,
        samesite=None,
        max_age=2678401,
        path="/",
        domain=".example.com",
    )


@app.post("/cross-site")
def cross_site(response: Response):
    response.set_cookie(
        "cross_site_session",
        "PLACEHOLDER_RESET_TOKEN",
        httponly=True,
        secure=True,
        samesite="none",
        max_age=900,
        path="/auth",
    )


@app.post("/dynamic")
def dynamic(response: Response):
    response.set_cookie("dynamic_session", "PLACEHOLDER_RESET_TOKEN", **cookie_options_from_config())


@app.post("/headers")
def headers(response: Response):
    response.headers["Set-Cookie"] = "header_session=PLACEHOLDER_RESET_TOKEN; HttpOnly; Secure; SameSite=Lax; Max-Age=2678401; Path=/; Domain=.example.com"
    response.headers.append(
        "Set-Cookie",
        "header_cross=PLACEHOLDER_RESET_TOKEN; HttpOnly; Secure; SameSite=None; Max-Age=900; Path=/auth",
    )


def cookie_options_from_config():
    return {"httponly": True, "secure": True}
