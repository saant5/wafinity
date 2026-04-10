import math
import re
from collections import Counter

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent

def extract_features(payload: str):
    """
    Convert a request payload string into numeric features for anomaly detection.
    Keep it lightweight + fast.
    """
    p = payload or ""
    p_low = p.lower()

    length = len(p)
    entropy = shannon_entropy(p_low)

    # counts of suspicious characters
    count_quote = p.count("'") + p.count('"')
    count_angle = p.count("<") + p.count(">")
    count_sql_tokens = len(re.findall(r"\b(select|union|drop|insert|update|delete|or|and)\b", p_low))
    count_script = len(re.findall(r"<script|onerror=|onload=|javascript:", p_low))
    count_cmd = len(re.findall(r"(\|\|)|(&&)|(;)|(\|)", p))
    count_traversal = p_low.count("../") + p_low.count("..\\")

    # encoded patterns
    count_pct = p.count("%")
    count_hex = len(re.findall(r"%[0-9a-fA-F]{2}", p))
    has_base64ish = 1 if re.fullmatch(r"[A-Za-z0-9+/=\s]{20,}", p.strip() or "") else 0

    # ratio features (avoid div by zero)
    denom = length if length > 0 else 1
    pct_ratio = count_pct / denom
    quote_ratio = count_quote / denom

    return [
        float(length),
        float(entropy),
        float(count_quote),
        float(count_angle),
        float(count_sql_tokens),
        float(count_script),
        float(count_cmd),
        float(count_traversal),
        float(count_pct),
        float(count_hex),
        float(has_base64ish),
        float(pct_ratio),
        float(quote_ratio),
    ]