import os
from flask import request

# Simple API key auth (demo). Put your real key in environment variable.
DEFAULT_KEY = "dev-key-123"
API_KEY = os.getenv("WAFINITY_API_KEY", DEFAULT_KEY)

def require_api_key():
    key = request.headers.get("X-API-Key")
    if not key or key != API_KEY:
        return False
    return True