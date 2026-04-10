from ai_engine.model import create_model, save_model
from ai_engine.features import extract_features

def train(normal_payloads):
    X = []

    for p in normal_payloads:
        X.append(extract_features(p))

    model = create_model()
    model.fit(X)
    save_model(model)
    print("✅ AI Anomaly Model Trained")