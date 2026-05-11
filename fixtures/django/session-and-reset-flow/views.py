from datetime import timedelta

from django.contrib.auth import logout
from django.core import signing
from django.http import HttpResponse
from django.utils import timezone


def issue_reset_token(user):
    payload = {
        "sub": user.pk,
        "token": "PLACEHOLDER_RESET_TOKEN",
        "expires_at": (timezone.now() + timedelta(minutes=30)).isoformat(),
    }
    return signing.dumps(payload, salt="password-reset")


def complete_logout(request):
    revoke_user_sessions(request.user.pk)
    logout(request)
    response = HttpResponse(status=204)
    response.delete_cookie("sessionid")
    return response


def revoke_user_sessions(user_id):
    return {"revoked_user": user_id}
