import requests
import certifi

DEFAULT_HEADERS = {
    "User-Agent": "WAFinityEnterpriseScanner/1.0"
}

def fetch_url(url: str, timeout: int = 10):
    """
    Always returns a dict.
    Never returns None.
    """
    try:
        r = requests.get(
            url,
            headers=DEFAULT_HEADERS,
            timeout=timeout,
            allow_redirects=True,
            verify=certifi.where()
        )
        return {
            "ok": True,
            "status_code": r.status_code,
            "final_url": r.url,
            "content_type": r.headers.get("Content-Type", ""),
            "body": r.text
        }

    except requests.exceptions.RequestException as e:
        return {
            "ok": False,
            "error_type": type(e).__name__,
            "error": str(e)
        }