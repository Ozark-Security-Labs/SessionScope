from django.http import JsonResponse

# Django runtime set_cookie is covered here. SESSION_COOKIE_* settings remain broader for settings-derived sessionid evidence.
def login(request):
    response = JsonResponse({"ok": True})
    response.set_cookie("__Host-session", "PLACEHOLDER_RESET_TOKEN", httponly=True, secure=False, samesite="Lax", path="/auth", domain="example.com")
    response.set_cookie("__Secure-refresh", "PLACEHOLDER_RESET_TOKEN", httponly=True, samesite="Strict")
    response.set_cookie("prefs", "PLACEHOLDER_RESET_TOKEN", httponly=True, secure=True, samesite="Lax", domain=".example.com")
    return response
