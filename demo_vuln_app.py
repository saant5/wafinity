from flask import Flask, request

app = Flask(__name__)

@app.get("/")
def home():
    return """
    <h2>Demo Vulnerable App (Local Only)</h2>
    <form method="get" action="/search">
      <input name="q" placeholder="search">
      <button type="submit">Search</button>
    </form>
    """

@app.get("/search")
def search():
    q = request.args.get("q","")
    # Intentionally vulnerable reflection (for demo only)
    return f"<h3>Results for:</h3> {q}"

if __name__ == "__main__":
    app.run(port=5001, debug=True)