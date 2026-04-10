from flask import Flask, request

app = Flask(__name__)

@app.get("/")
def home():
    return """
    <h2>✅ Protected App is Running</h2>
    <p>Try:</p>
    <ul>
      <li><a href="/search?q=hello">/search?q=hello</a></li>
      <li><a href="/search?q=%3Cscript%3Ealert(1)%3C/script%3E">XSS test</a></li>
      <li><a href="/login?user=admin&pass=' OR 1=1 --">SQLi test</a></li>
    </ul>
    """

@app.get("/search")
def search():
    q = request.args.get("q", "")
    return f"<h3>Search</h3><p>You searched for: <b>{q}</b></p>"

@app.get("/login")
def login():
    user = request.args.get("user", "")
    pw = request.args.get("pass", "")
    return f"<h3>Login</h3><p>User={user} Pass={pw}</p>"

@app.post("/submit")
def submit():
    data = request.get_data(as_text=True)[:2000]
    return f"<h3>POST Received</h3><pre>{data}</pre>"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)