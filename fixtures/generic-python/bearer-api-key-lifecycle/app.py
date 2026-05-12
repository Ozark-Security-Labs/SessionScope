import os
import secrets

import httpx


API_KEY = "PLACEHOLDER_API_KEY_DO_NOT_USE"


def issue_service_token(user_id):
    service_token = secrets.token_urlsafe(32)
    token_store.create(
        {
            "token": service_token,
            "expires_at": service_token_expires_at,
            "user_id": user_id,
        }
    )
    return service_token


def call_partner_api(user_id):
    service_token = issue_service_token(user_id)
    return httpx.get(
        "https://partner.example.test/accounts",
        headers={
            "Authorization": f"Bearer {service_token}",
            "X-API-Key": os.environ["API_KEY"],
        },
    )


def authorize_request(request):
    incoming = request.headers.get("authorization")
    stored = api_key_store.find_one({"token": incoming})
    return stored is not None


def revoke_service_token(service_token):
    disable_service_token(service_token)


def unsafe_query_transmission(access_token):
    return httpx.get("https://partner.example.test/callback", params={"access_token": access_token})


def provider_managed_token():
    return auth0_provider.token(audience="internal-api")


sample_documentation = "Authorization header expected"
