from fastapi import FastAPI, Response

app = FastAPI()

@app.post("/login")
def login(response: Response):
    response.set_cookie("__Host-session", "PLACEHOLDER_RESET_TOKEN", httponly=True, secure=False, samesite="lax", path="/auth", domain="example.com")
    response.set_cookie("__Secure-refresh", "PLACEHOLDER_RESET_TOKEN", httponly=True, samesite="strict")
    response.set_cookie("chips", "PLACEHOLDER_RESET_TOKEN", httponly=True, secure=True, samesite="none", partitioned=True)
    response.set_cookie("prefs", "PLACEHOLDER_RESET_TOKEN", httponly=True, secure=True, samesite="lax", domain=".example.com")
    return {"ok": True}
