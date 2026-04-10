from functools import wraps
from flask import jsonify
from api_gateway.jwt_auth import verify_token

def require_role(*roles: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            ok, data = verify_token()
            if not ok:
                return jsonify({"blocked": True, "reason": "Unauthorized"}), 401

            role = data.get("role")
            if role not in roles:
                return jsonify({"blocked": True, "reason": "Forbidden", "need_roles": list(roles), "got": role}), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator

def require_scope(required_scope: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            ok, data = verify_token()
            if not ok:
                return jsonify({"blocked": True, "reason": "Unauthorized"}), 401

            scopes = data.get("scopes") or []
            if required_scope not in scopes:
                return jsonify({"blocked": True, "reason": "Forbidden", "need_scope": required_scope, "got_scopes": scopes}), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator