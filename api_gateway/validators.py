def validate_json(required_fields: list[str], data: dict):
    if not isinstance(data, dict):
        return False, "JSON body must be an object"

    missing = [f for f in required_fields if f not in data]
    if missing:
        return False, f"Missing fields: {', '.join(missing)}"

    return True, "OK"