import os

import httpx


def server_api_key_call():
    api_key = os.environ["API_KEY"]
    return httpx.get(
        "https://billing.example.invalid/api",
        headers={"X-API-Key": api_key},
    )
