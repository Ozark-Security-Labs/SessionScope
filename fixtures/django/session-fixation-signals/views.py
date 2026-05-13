from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse


def login_with_cycle_key(request):
    user = authenticate(
        username=request.POST.get("email"),
        password=request.POST.get("password"),
    )
    request.session.cycle_key()
    request.session["user_id"] = user.pk
    return JsonResponse({"ok": True})


def login_with_framework_default(request):
    user = authenticate(
        username=request.POST.get("email"),
        password=request.POST.get("password"),
    )
    login(request, user)
    return JsonResponse({"ok": True})


def legacy_login(request):
    user = authenticate(
        username=request.POST.get("email"),
        password=request.POST.get("password"),
    )
    request.session["user_id"] = user.pk
    return JsonResponse({"ok": True})


def promote_to_admin(request):
    request.session["role"] = "admin"
    return JsonResponse({"ok": True})


def logout_view(request):
    logout(request)
    return JsonResponse({"ok": True})
