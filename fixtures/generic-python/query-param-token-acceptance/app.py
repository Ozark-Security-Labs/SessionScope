from fastapi import Query


def fastapi_callback(access_token: str = Query(None), api_key: str = Query(alias="api_key")):
    return bool(access_token and api_key)


def django_reset(request):
    token = request.GET.get("token")
    return consume_reset_token(token)


def drf_refresh(request):
    return request.query_params.get("refresh_token")


def django_verify_email(request):
    token = request.GET["token"]
    return consume_email_verification(token)


def dynamic_token_name(request):
    token_param_name = configured_token_param_name()
    return request.GET.get(token_param_name)


def ignored_pagination(request):
    return request.GET.get("page_token") or request.GET.get("state") or request.GET.get("code")
