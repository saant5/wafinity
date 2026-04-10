import os
import joblib

from ai.features import extract_features

MODEL_PATH = os.path.join("models", "ai_isoforest.joblib")
SCALER_PATH = os.path.join("models", "ai_scaler.joblib")

_model = None
_scaler = None

def _load():
    global _model, _scaler
    if _model is None or _scaler is None:
        if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
            raise FileNotFoundError("AI model not found. Run: python ai\\trainer.py")
        _model = joblib.load(MODEL_PATH)
        _scaler = joblib.load(SCALER_PATH)

def predict_ai(payload: str):
    """
    Returns:
      ai_score: 0..100 (higher = more suspicious)
      ai_malicious: bool
    """
    _load()
    feats = extract_features(payload)
    Xs = _scaler.transform([feats])

    # IsolationForest:
    # decision_function: higher = more normal, lower = more abnormal
    normality = float(_model.decision_function(Xs)[0])

# More aggressive anomaly mapping
    score = int(max(0, min(100, (0.5 - normality) * 120)))

    ai_malicious = score >= 40   # lower threshold threshold (tune later)

    return {
        "ai_score": int(round(score)),
        "ai_malicious": bool(ai_malicious),
        "ai_normality": normality
    }