from core.detector import detect_patterns
from ai.predictor import AIPredictor

ai = AIPredictor()

def analyze(payload: str):
    # Step 1: Rule-based detection
    rule_threats = detect_patterns(payload)

    # Step 2: AI detection
    ai_result = ai.predict(payload)

    # Step 3: Final decision logic
    if rule_threats:
        decision = "BLOCK"
        threats = rule_threats
        confidence = 1.0
    elif ai_result["label"] == "ANOMALY":
        decision = "BLOCK"
        threats = ["ANOMALY"]
        confidence = ai_result["prob_attack"]
    else:
        decision = "ALLOW"
        threats = []
        confidence = ai_result["prob_attack"]

    return {
        "payload": payload,
        "decision": decision,
        "threats": threats,
        "ai_confidence": round(confidence, 3)
    }