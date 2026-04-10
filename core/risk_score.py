def risk_score(threats):
    score = 0
    for t in threats:
        if t == "SQL_INJECTION":
            score += 50
        elif t == "XSS":
            score += 40
        else:
            score += 10
    return min(score, 100)