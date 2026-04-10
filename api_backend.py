from flask import Flask, request, jsonify
import time
import jwt  # PyJWT

app = Flask(__name__)

JWT_SECRET = "WAFINITY_SECRET_123"   # same secret must be used in gateway
JWT_ALGO = "HS256"

@app.get("/")
def home():
    return jsonify({"service": "API Backend", "status": "ok"})

@app.post("/auth/login")
def login():
    """
    Demo login: send JSON {"user":"alice","role":"admin"} to get JWT
    """
    data = request.get_json(force=True) or {}
    user = data.get("user", "guest")
    role = data.get("role", "user")

    payload = {
        "sub": user,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,  # 1 hour
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    return jsonify({"token": token})

@app.get("/api/public")
def public_api():
    return jsonify({"message": "Public endpoint - no auth required"})

@app.get("/api/profile")
def profile():
    # Gateway will inject these headers after JWT validation
    user = request.headers.get("X-User", "unknown")
    role = request.headers.get("X-Role", "unknown")
    return jsonify({"user": user, "role": role})

@app.get("/api/admin")
def admin():
    return jsonify({"secret": "Only ADMIN should reach here ✅"})

@app.post("/api/echo")
def echo():
    body = request.get_data(as_text=True)[:2000]
    return jsonify({"echo": body})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False)