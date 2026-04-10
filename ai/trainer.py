from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

from ai.features import extract_features

MODEL_PATH = os.path.join("models", "ai_isoforest.joblib")
SCALER_PATH = os.path.join("models", "ai_scaler.joblib")


def train(benign_samples):
    X = [extract_features(s) for s in benign_samples]

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    # contamination: expected fraction of anomalies in normal traffic
    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42
    )
    model.fit(Xs)

    os.makedirs("models", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    return MODEL_PATH, SCALER_PATH


if __name__ == "__main__":
    # Minimal benign dataset (you can expand later)
    benign = [
        "GET /",
        "GET /home",
        "GET /products?id=12",
        "GET /search?q=iphone",
        "POST /login username=alice&password=hello123",
        "GET /profile",
        "GET /api/users?page=1&limit=10",
        "POST /contact name=test&message=hi",
        "GET /assets/style.css",
        "GET /favicon.ico",
    ]

    mp, sp = train(benign)
    print("✅ AI model trained:")
    print("  Model :", mp)
    print("  Scaler:", sp)