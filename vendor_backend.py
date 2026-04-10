from flask import Flask, render_template, request, abort
import os

# Must match gateway.py
INTERNAL_GATEWAY_TOKEN = "wafinity-internal-2026"

app = Flask(
    __name__,
    template_folder=os.path.join("vendor_app", "templates"),
    static_folder=os.path.join("vendor_app", "static"),
    static_url_path="/vendor-static"
)

PRODUCTS = [
    {"id": 1, "name": "Rice Bag", "price": 1200, "category": "Groceries"},
    {"id": 2, "name": "Cooking Oil", "price": 180, "category": "Groceries"},
    {"id": 3, "name": "Sugar", "price": 55, "category": "Groceries"},
    {"id": 4, "name": "Tea Powder", "price": 95, "category": "Beverages"},
    {"id": 5, "name": "Milk Packet", "price": 30, "category": "Dairy"},
    {"id": 6, "name": "Soap", "price": 40, "category": "Personal Care"},
]

def require_gateway():
    token = request.headers.get("X-Gateway-Auth", "")
    if token != INTERNAL_GATEWAY_TOKEN:
        abort(403)

@app.route("/")
def home():
    require_gateway()
    return render_template("vendor_home.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    require_gateway()
    message = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        message = f"Welcome, {username}" if username else "Login submitted"
    return render_template("vendor_login.html", message=message)

@app.route("/products")
def products():
    require_gateway()
    return render_template("vendor_products.html", products=PRODUCTS)

@app.route("/search")
def search():
    require_gateway()
    query = request.args.get("q", "").strip().lower()
    filtered = PRODUCTS
    if query:
        filtered = [
            p for p in PRODUCTS
            if query in p["name"].lower() or query in p["category"].lower()
        ]
    return render_template("vendor_search.html", products=filtered, query=query)

@app.route("/contact", methods=["GET", "POST"])
def contact():
    require_gateway()
    message = None
    if request.method == "POST":
        message = "Message sent successfully"
    return render_template("vendor_contact.html", message=message)



if __name__ == "__main__":
    port = int(os.environ.get("VENDOR_PORT", 5001))
    app.run(host="127.0.0.1", port=port, debug=False)