import os
from functools import wraps

from flask import Flask, jsonify, request, Response

from api_gateway.auth import require_api_key
from api_gateway.jwt_auth import create_token, verify_token
from api_gateway.logger import log_event

app = Flask(__name__)

PROJECT_NAME = os.environ.get("PROJECT_NAME", "WAFinity API Gateway")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
ANALYST_PASSWORD = os.environ.get("ANALYST_PASSWORD", "")
USER_PASSWORD = os.environ.get("USER_PASSWORD", "")


def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def json_error(message: str, status: int = 400):
    return jsonify({"error": message}), status


def auth_required(allowed_roles=None):
    if allowed_roles is None:
        allowed_roles = []

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            ip = client_ip()

            ok_jwt, jwt_data = verify_token()
            if ok_jwt:
                role = jwt_data.get("role", "")
                request.jwt_user = jwt_data

                if allowed_roles and role not in allowed_roles:
                    log_event({
                        "type": "RBAC_BLOCK",
                        "ip": ip,
                        "path": request.path,
                        "role": role,
                        "reason": "role_not_allowed",
                    })
                    return json_error("Forbidden", 403)

                return fn(*args, **kwargs)

            if not require_api_key():
                log_event({
                    "type": "AUTH_BLOCK",
                    "ip": ip,
                    "path": request.path,
                    "reason": str(jwt_data),
                })
                return json_error("Unauthorized", 401)

            return fn(*args, **kwargs)

        return wrapper
    return decorator


@app.get("/")
def home():
    html = f"""
    <!doctype html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>{PROJECT_NAME}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #0f172a;
                color: white;
                margin: 0;
                padding: 40px;
            }}
            .card {{
                max-width: 520px;
                margin: 0 auto;
                background: #111827;
                padding: 24px;
                border-radius: 16px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            }}
            h1 {{
                margin-top: 0;
                font-size: 24px;
            }}
            label {{
                display: block;
                margin-top: 14px;
                margin-bottom: 6px;
            }}
            input, button {{
                width: 100%;
                padding: 10px 12px;
                border-radius: 10px;
                border: 1px solid #374151;
                background: #1f2937;
                color: white;
                box-sizing: border-box;
            }}
            button {{
                margin-top: 16px;
                cursor: pointer;
                background: #2563eb;
                border: none;
                font-weight: bold;
            }}
            pre {{
                background: #020617;
                padding: 12px;
                border-radius: 10px;
                overflow-x: auto;
                white-space: pre-wrap;
                word-break: break-word;
            }}
            .muted {{
                color: #94a3b8;
                font-size: 14px;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>{PROJECT_NAME}</h1>
            <p class="muted">Login uses environment variables. No hardcoded passwords.</p>

            <label>Username</label>
            <input id="user" value="admin" type="text" placeholder="username" />

            <label>Password</label>
            <input id="pass" value="" type="password" placeholder="password" />

            <button onclick="login()">Login</button>

            <h3>Response</h3>
            <pre id="out">Not logged in</pre>
        </div>

        <script>
        async function login() {{
            const username = document.getElementById("user").value;
            const password = document.getElementById("pass").value;

            const res = await fetch("/api/v1/login", {{
                method: "POST",
                headers: {{
                    "Content-Type": "application/json"
                }},
                body: JSON.stringify({{ username, password }})
            }});

            const data = await res.json();
            document.getElementById("out").textContent = JSON.stringify(data, null, 2);

            if (data.token) {{
                localStorage.setItem("wafinity_token", data.token);
            }}
        }}
        </script>
    </body>
    </html>
    """
    return Response(html, mimetype="text/html")


@app.post("/api/v1/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    admin_scopes = ["logs:read", "logs:delete", "rules:write"]
    analyst_scopes = ["logs:read"]
    user_scopes = []

    if username == "admin" and password == ADMIN_PASSWORD:
        token = create_token(username, role="admin", scopes=admin_scopes)
        return jsonify({
            "token": token,
            "role": "admin",
            "scopes": admin_scopes
        })

    if username == "analyst" and password == ANALYST_PASSWORD:
        token = create_token(username, role="analyst", scopes=analyst_scopes)
        return jsonify({
            "token": token,
            "role": "analyst",
            "scopes": analyst_scopes
        })

    if username == "user" and password == USER_PASSWORD:
        token = create_token(username, role="user", scopes=user_scopes)
        return jsonify({
            "token": token,
            "role": "user",
            "scopes": user_scopes
        })

    log_event({
        "type": "LOGIN_FAIL",
        "ip": client_ip(),
        "path": request.path,
        "username": username,
        "reason": "invalid_credentials",
    })
    return jsonify({"error": "Invalid credentials"}), 401


@app.get("/api/v1/public")
def public():
    return jsonify({
        "message": "Public endpoint is working",
        "project": PROJECT_NAME
    })


@app.get("/api/v1/profile")
@auth_required(allowed_roles=["admin", "analyst", "user"])
def profile():
    user = getattr(request, "jwt_user", {})
    return jsonify({
        "message": "Authenticated",
        "user": user
    })


@app.get("/api/v1/admin")
@auth_required(allowed_roles=["admin"])
def admin_only():
    return jsonify({
        "message": "Admin access granted"
    })


@app.get("/api/v1/analyst")
@auth_required(allowed_roles=["admin", "analyst"])
def analyst_view():
    return jsonify({
        "message": "Analyst/Admin access granted"
    })


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "api_gateway",
        "project": PROJECT_NAME
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("API_GATEWAY_PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)