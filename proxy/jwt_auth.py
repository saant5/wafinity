import os
import jwt

JWT_SECRET = os.environ.get("WAFINITY_JWT_SECRET", "")
JWT_ALGO = "HS256"


def verify_bearer(auth_header: str):
    if not auth_header:
        return False, None, "Missing Authorization header"

    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0] != "Bearer":
        return False, None, "Authorization must be: Bearer <token>"

    token = parts[1].strip()

    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return True, claims, "OK"
    except jwt.ExpiredSignatureError:
        return False, None, "Token expired"
    except jwt.InvalidTokenError:
        return False, None, "Invalid token"