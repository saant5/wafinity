from sklearn.ensemble import IsolationForest
import joblib
import os

MODEL_PATH = "ai_engine/anomaly_model.pkl"

def create_model():
    model = IsolationForest(
        n_estimators=200,
        contamination=0.03,
        random_state=42
    )
    return model

def save_model(model):
    joblib.dump(model, MODEL_PATH)

def load_model():
    if not os.path.exists(MODEL_PATH):
        return None
    return joblib.load(MODEL_PATH)