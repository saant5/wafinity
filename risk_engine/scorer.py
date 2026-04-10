# risk_engine/scorer.py

def calculate_risk(attacks, anomaly_score):
    """
    attacks: list of detected attack types (e.g. ["SQL_INJECTION", "XSS"])
    anomaly_score: numeric anomaly score from ML/AI engine
    """

    score = 0

    # Each real attack has high weight
    for attack in attacks:
        if attack != "ANOMALY":
            score += 30   # weight per real attack

    # Anomaly has lower weight
    score += anomaly_score

    return score