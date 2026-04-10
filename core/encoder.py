import base64
import urllib.parse

def decode_payload(payload: str):
    decoded = [payload]

    # URL decode
    try:
        decoded.append(urllib.parse.unquote(payload))
    except:
        pass

    # Base64 decode
    try:
        decoded.append(base64.b64decode(payload).decode())
    except:
        pass

    return list(set(decoded))