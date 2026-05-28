import os

import httpx
from fastapi import Depends, FastAPI, Request
from fastapi.security import OAuth2PasswordBearer

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


@app.get("/api/orders")
def forward_to_orders(request: Request):
    authorization = request.headers.get("authorization")
    return httpx.get(
        "https://orders.example.invalid/api/orders",
        headers={"Authorization": authorization},
    )


@app.get("/api/orders/service")
def call_orders_with_service_token():
    service_token = os.environ["ORDERS_TOKEN"]
    return httpx.get(
        "https://orders.example.invalid/api/orders",
        headers={
            "X-Service-Token": service_token,
            "audience": "orders_api",
        },
    )


@app.get("/api/provider")
def provider_managed_token(provider: str = Depends(oauth2_scheme)):
    return provider_client.token(token="PLACEHOLDER_RESET_TOKEN")
