def password_change_complete(request):
    request.user.set_password(request.POST["new_password"])
    request.user.save()
    return {"ok": True}
