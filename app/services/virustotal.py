import itertools
import threading
import requests
import base64
from app.config import settings
from app.utils.rate_limiter import RateLimiter


def _load_keys() -> list[str]:
    """
    VIRUSTOTAL_API_KEY can hold one key or several, comma- or newline-
    separated. Each valid key gets its own 4/min bucket and calls round-robin
    across all of them, so N keys give roughly N x virustotal_rpm effective
    throughput instead of being stuck behind one shared limit.
    """
    raw = settings.virustotal_api_key or ""
    keys = [k.strip() for k in raw.replace("\n", ",").split(",")]
    return [k for k in keys if k and "your_" not in k]


_VT_KEYS = _load_keys()
_VT_LIMITERS = {key: RateLimiter(max_calls=settings.virustotal_rpm, period_seconds=60) for key in _VT_KEYS}
_vt_key_cycle = itertools.cycle(_VT_KEYS) if _VT_KEYS else None
_vt_cycle_lock = threading.Lock()


def _next_vt_key() -> str:
    with _vt_cycle_lock:
        return next(_vt_key_cycle)


def check_virustotal(url: str) -> dict:
    """
    Returns a rich dict of VirusTotal data for the given URL.
    Falls back to mock data if no valid API key is configured.
    """
    if not _VT_KEYS:
        # Mock fallback
        is_malicious = "malicious" in url.lower()
        return {
            "malicious": 10 if is_malicious else 0,
            "suspicious": 0,
            "harmless": 60,
            "undetected": 25,
            "timeout": 0,
            "final_url": url,
            "title": "N/A (mock)",
            "tags": [],
            "categories": {},
            "redirection_chain": [],
            "times_submitted": 0,
            "last_http_response_code": None,
            "last_analysis_results": {},
            "threat_names": [],
            "reputation": 0,
            "mock": True,
        }

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        api_key = _next_vt_key()
        headers = {"x-apikey": api_key}
        print(f"[VirusTotal] key ...{api_key[-4:]} ({_VT_KEYS.index(api_key) + 1}/{len(_VT_KEYS)}) -> {url}")

        _VT_LIMITERS[api_key].acquire()
        response = requests.get(api_url, headers=headers, timeout=15)

        if response.status_code == 404:
            # Genuinely not in VT's database — this is a real "clean/unknown" result.
            return _empty_vt_result()

        if response.status_code != 200:
            # Rate-limited (429), server error, etc. — this is NOT the same as
            # "checked and clean," so it's tagged with an explicit error instead
            # of silently returning the same shape as a clean scan.
            print(f"VT API Error: {response.status_code} - {response.text}")
            result = _empty_vt_result()
            result["error"] = (
                "Rate limited by VirusTotal (429) — result not checked"
                if response.status_code == 429
                else f"VirusTotal HTTP {response.status_code}"
            )
            return result

        raw = response.json()
        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        # Collect engines that flagged as malicious or suspicious
        threat_names = [
            engine
            for engine, detail in results.items()
            if detail.get("category") in ("malicious", "suspicious")
        ]

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "final_url": attrs.get("last_final_url", url),
            "title": attrs.get("title", ""),
            "tags": attrs.get("tags", []),
            "categories": attrs.get("categories", {}),
            "redirection_chain": attrs.get("redirection_chain", []),
            "times_submitted": attrs.get("times_submitted", 0),
            "last_http_response_code": attrs.get("last_http_response_code"),
            "last_analysis_results": results,
            "threat_names": threat_names,
            "reputation": attrs.get("reputation", 0),
            "mock": False,
        }

    except Exception as e:
        print(f"VT integration error: {e}")
        result = _empty_vt_result()
        result["error"] = f"VirusTotal integration error: {e}"
        return result


def _empty_vt_result() -> dict:
    return {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "timeout": 0,
        "final_url": "",
        "title": "",
        "tags": [],
        "categories": {},
        "redirection_chain": [],
        "times_submitted": 0,
        "last_http_response_code": None,
        "last_analysis_results": {},
        "threat_names": [],
        "reputation": 0,
        "mock": False,
    }
