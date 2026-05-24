def password_change_complete(request):
    request.user.set_password(request.POST["new_password"])
    request.user.save()
    revoke_all_sessions(request.user.pk)
    bump_token_version(request.user.pk)
    return {"ok": True}
