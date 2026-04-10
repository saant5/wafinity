from flask import Flask, render_template_string, request
import requests
import json

app = Flask(__name__)

TARGET_URL = "http://127.0.0.1:5000/analyze"

PRESET_ATTACKS = {
    "SQL Injection": "' OR 1=1 --",
    "XSS": "<script>alert(1)</script>",
    "Path Traversal": "../../etc/passwd",
    "Command Injection": "; ls",
    "AI Anomaly": "UNION SELECT password FROM users WHERE username='admin'"
}

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Attack Application</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #111827;
            color: white;
            text-align: center;
            padding-top: 70px;
        }

        .search-box {
            width: 600px;
            padding: 16px;
            border-radius: 30px;
            border: none;
            font-size: 16px;
            outline: none;
        }

        .btn {
            margin-top: 20px;
            padding: 12px 22px;
            border: none;
            border-radius: 30px;
            background: #38bdf8;
            color: black;
            font-weight: bold;
            cursor: pointer;
        }

        .preset-wrap {
            margin-top: 25px;
        }

        .preset-btn {
            margin: 6px;
            padding: 10px 16px;
            border: none;
            border-radius: 20px;
            background: #1f2937;
            color: white;
            cursor: pointer;
            font-size: 14px;
        }

        .preset-btn:hover {
            background: #374151;
        }

        .msg {
            margin: 25px auto 0;
            width: 80%;
            max-width: 800px;
            color: #22c55e;
            white-space: pre-wrap;
            text-align: left;
            background: #0f172a;
            padding: 15px;
            border-radius: 12px;
        }

        .title {
            margin-bottom: 25px;
        }
    </style>

    <script>
        function setPayload(value) {
            document.getElementById("payload").value = value;
        }
    </script>
</head>
<body>
    <div class="title">
        <h2>http://127.0.0.1:5002</h2>
        <h1>Attack Application</h1>
        <p>Use preset attacks or type your own payload</p>
    </div>

    <div class="preset-wrap">
        {% for name, value in presets.items() %}
            <button class="preset-btn" type="button" onclick='setPayload({{ value|tojson }})'>
                {{ name }}
            </button>
        {% endfor %}
    </div>

    <form method="POST">
        <div style="margin-top: 25px;">
            <input
                id="payload"
                class="search-box"
                type="text"
                name="payload"
                placeholder="Search (attacks will be done in this search option)"
                value="{{ payload }}"
            >
        </div>
        <button class="btn" type="submit">Send Attack</button>
    </form>

    {% if message %}
        <div class="msg">{{ message }}</div>
    {% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def home():
    message = ""
    payload = ""

    if request.method == "POST":
        payload = request.form.get("payload", "")

        try:
            r = requests.post(
                TARGET_URL,
                json={
                    "payload": payload,
                    "source": "attack_app",
                    "attack_name": "PRESET_OR_CUSTOM"
                },
                timeout=5
            )

            try:
                response_json = r.json()
                message = json.dumps(response_json, indent=2)
            except:
                message = r.text

        except Exception as e:
            message = f"Error: {e}"

    return render_template_string(
        HTML,
        message=message,
        payload=payload,
        presets=PRESET_ATTACKS
    )

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=True)