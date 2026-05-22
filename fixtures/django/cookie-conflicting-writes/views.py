from django.http import JsonResponse

# Runtime set_cookie coverage only; settings-derived sessionid defaults are intentionally separate.
def login(request):
    response = JsonResponse({"ok": True})
    response.set_cookie("session", "PLACEHOLDER_RESET_TOKEN", httponly=True, secure=True, samesite="Lax")
    response.set_cookie("session", "PLACEHOLDER_RESET_TOKEN", httponly=True, secure=False, samesite="None")
    response.set_cookie("csrf", "PLACEHOLDER_RESET_TOKEN", httponly=True, secure=True, samesite="Strict")
    return response
