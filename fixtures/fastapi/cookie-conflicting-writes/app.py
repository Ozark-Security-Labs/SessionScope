from fastapi import FastAPI, Response

app = FastAPI()

@app.post("/login")
def login(response: Response):
    response.set_cookie("session", "PLACEHOLDER_RESET_TOKEN", httponly=True, secure=True, samesite="lax")
    response.set_cookie("session", "PLACEHOLDER_RESET_TOKEN", httponly=True, secure=False, samesite="none")
    response.set_cookie("csrf", "PLACEHOLDER_RESET_TOKEN", httponly=True, secure=True, samesite="strict")
    return {"ok": True}

@app.post("/refresh")
def refresh(response: Response):
    response.set_cookie("session", "PLACEHOLDER_RESET_TOKEN", httponly=True, secure=True, samesite="strict")
    return {"ok": True}
