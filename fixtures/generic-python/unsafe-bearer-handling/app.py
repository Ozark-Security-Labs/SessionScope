import os
import secrets
import httpx


API_KEY = os.environ["API_KEY"]


def issue_service_token(user_id):
    service_token = secrets.token_urlsafe(32)
    token_store.create({"token": service_token, "owner": user_id})
    return service_token


def forward_api_key(api_key):
    return httpx.get(f"https://partner.example.test/callback?api_key={api_key}")


def read_inbound_key(request):
    return request.headers.get("X-API-Key")


def provider_managed_token(provider):
    return provider.token()
