import requests
import base64
from app.config import settings


def check_virustotal(url: str) -> dict:
    """
    Returns a rich dict of VirusTotal data for the given URL.
    Falls back to mock data if no valid API key is configured.
    """
    if not settings.virustotal_api_key or "your_" in settings.virustotal_api_key:
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
        headers = {"x-apikey": settings.virustotal_api_key}

        response = requests.get(api_url, headers=headers, timeout=15)

        if response.status_code == 404:
            return _empty_vt_result()

        if response.status_code != 200:
            print(f"VT API Error: {response.status_code} - {response.text}")
            return _empty_vt_result()

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
        return _empty_vt_result()


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
