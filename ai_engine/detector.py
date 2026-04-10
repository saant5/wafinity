from ai_engine.model import load_model
from ai_engine.features import extract_features

model = load_model()

def anomaly_score(payload):
    global model
    if model is None:
        return 0   # safe if not trained yet

    features = extract_features(payload)
    score = model.decision_function([features])[0]
    anomaly = model.predict([features])[0]

    # anomaly == -1 → abnormal
    if anomaly == -1:
        return abs(score) * 100
    return 0