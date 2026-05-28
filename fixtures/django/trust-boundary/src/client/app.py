import os


def client_config():
    api_key = os.environ.get("NEXT_PUBLIC_API_KEY")
    return {"api_key": api_key}
