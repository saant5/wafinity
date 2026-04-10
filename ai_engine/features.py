import re
import urllib.parse

def extract_features(payload: str):
    decoded = urllib.parse.unquote(payload.lower())

    features = {}

    features["length"] = len(decoded)
    features["num_digits"] = sum(c.isdigit() for c in decoded)
    features["num_special"] = sum(not c.isalnum() for c in decoded)
    features["num_sql_keywords"] = len(re.findall(r"(select|union|drop|or|and|insert|where)", decoded))
    features["num_tags"] = len(re.findall(r"<.*?>", decoded))
    features["num_paths"] = decoded.count("../")
    features["entropy"] = len(set(decoded)) / (len(decoded)+1)

    return list(features.values())