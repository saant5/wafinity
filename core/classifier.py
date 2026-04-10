def classify(threats):
    if not threats:
        return "CLEAN"

    if "SQL_INJECTION" in threats and "XSS" in threats:
        return "CRITICAL_ATTACK"

    if "SQL_INJECTION" in threats:
        return "SQL_ATTACK"

    if "XSS" in threats:
        return "XSS_ATTACK"

    return "SUSPICIOUS"