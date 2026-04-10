import os
import time
import jwt
from flask import request

JWT_SECRET = os.environ.get("WAFINITY_JWT_SECRET", "")
JWT_ALGO = "HS256"
JWT_EXP_SECONDS = 30 * 60


def create_token(username: str, role: str, scopes: list[str]):
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "scopes": scopes,
        "iat": now,
        "exp": now + JWT_EXP_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def verify_token():
    auth = request.headers.get("Authorization", "")

    if not auth.startswith("Bearer "):
        return False, "Missing Bearer token"

    token = auth.split(" ", 1)[1].strip()

    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return True, decoded
    except jwt.ExpiredSignatureError:
        return False, "Token expired"
    except jwt.InvalidTokenError:
        return False, "Invalid token"