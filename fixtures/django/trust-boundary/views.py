import os

import httpx
from django.http import JsonResponse
from django.views import View


class OrdersProxyView(View):
    def get(self, request):
        authorization = request.headers.get("Authorization")
        return httpx.get(
            "https://orders.example.invalid/api/orders",
            headers={"Authorization": authorization},
        )


class OrdersServiceView(View):
    def get(self, request):
        service_token = os.environ["ORDERS_TOKEN"]
        return httpx.get(
            "https://orders.example.invalid/api/orders",
            headers={
                "X-Service-Token": service_token,
                "audience": "orders_api",
            },
        )


class ProviderTokenView(View):
    def get(self, request):
        return provider_client.token(token="PLACEHOLDER_RESET_TOKEN")
