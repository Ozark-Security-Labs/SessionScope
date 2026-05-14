from datetime import timedelta

from django.contrib.auth import authenticate, login, logout
from django.core import signing
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
import jwt

JWT_SECRET = "PLACEHOLDER_SECRET_DO_NOT_USE"
ISSUER = "https://placeholder.issuer.invalid"
AUDIENCE = "placeholder-django"


def login_view(request):
    user = authenticate(username=request.POST.get("email"), password=request.POST.get("password"))
    request.session.cycle_key()
    login(request, user)
    request.session["user_id"] = user.pk
    token = jwt.encode(
        {"sub": user.pk, "iss": ISSUER, "aud": AUDIENCE, "exp": timezone.now() + timedelta(minutes=15)},
        JWT_SECRET,
        algorithm="HS256",
    )
    response = JsonResponse({"ok": True})
    response.set_cookie("sessionid", token, httponly=True, secure=True, samesite="Lax", max_age=900)
    return response


def current_user_from_token(token):
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=["HS256"],
        issuer=ISSUER,
        audience=AUDIENCE,
    )


def issue_signed_reset_token(user):
    payload = {
        "sub": user.pk,
        "token": "PLACEHOLDER_RESET_TOKEN",
        "expires_at": (timezone.now() + timedelta(minutes=30)).isoformat(),
    }
    return signing.dumps(payload, salt="password-reset")


def verify_signed_reset_token(token):
    return signing.loads(token, salt="password-reset", max_age=1800)


def refresh_view(request):
    previous_refresh_token = request.COOKIES.get("refresh_token")
    verify_refresh_token(previous_refresh_token)
    revoke_refresh_token(previous_refresh_token)
    response = JsonResponse({"refreshed": True})
    response.set_cookie("refresh_token", "PLACEHOLDER_RESET_TOKEN_ROTATED", httponly=True, secure=True, samesite="Strict", max_age=900)
    return response


def logout_view(request):
    revoke_user_sessions(request.user.pk)
    revoke_refresh_token(request.COOKIES.get("refresh_token"))
    logout(request)
    request.session.flush()
    response = HttpResponse(status=204)
    response.delete_cookie("sessionid")
    response.delete_cookie("refresh_token")
    return response


def verify_refresh_token(token):
    return {"token": token, "expires_at": timezone.now() + timedelta(minutes=15)}


def revoke_refresh_token(token):
    return {"revoked": token}


def revoke_user_sessions(user_id):
    return {"revoked_user": user_id}
