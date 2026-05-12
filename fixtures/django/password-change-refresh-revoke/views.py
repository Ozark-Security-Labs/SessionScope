def password_change_complete(request):
    revoke_refresh_tokens_for_user(request.user.pk)
    return {"ok": True}
