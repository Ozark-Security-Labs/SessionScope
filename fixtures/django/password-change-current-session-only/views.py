def password_change_complete(request):
    request.user.set_password(request.POST["new_password"])
    request.user.save()
    request.session.cycle_key()
    logout(request)
    return {"ok": True}
