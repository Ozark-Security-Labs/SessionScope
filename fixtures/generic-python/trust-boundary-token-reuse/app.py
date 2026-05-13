import os

import httpx


def forward_inbound_authorization(request):
    authorization = request.headers.get("authorization")
    return httpx.get(
        "https://orders.example.invalid/api/orders",
        headers={"Authorization": authorization},
    )


def call_orders_with_service_token():
    service_token = os.environ["ORDERS_TOKEN"]
    return httpx.get(
        "https://orders.example.invalid/api/orders",
        headers={
            "X-Service-Token": service_token,
            "audience": "orders_api",
        },
    )


def provider_managed_token(provider):
    return provider.token(token="PLACEHOLDER_RESET_TOKEN")
