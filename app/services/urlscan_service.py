import requests
from urllib.parse import urlparse
from app.config import settings

def check_urlscan(url: str):
    if not settings.urlscan_api_key:
        return {"error": "No API key configured"}

    # Normalise: bare domains like 'welthwest.com' have no scheme,
    # so urlparse puts everything in 'path', not 'netloc'.
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    domain = urlparse(url).netloc.split(':')[0]
    if not domain:
        return {"error": "Invalid URL format"}

    headers = {"API-Key": settings.urlscan_api_key}
    
    try:
        response = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}",
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            results = data.get("results", [])
            if results:
                # Get the most recent scan
                latest = results[0]
                task = latest.get("task", {})
                page = latest.get("page", {})
                return {
                    "malicious": latest.get("verdicts", {}).get("overall", {}).get("malicious", False),
                    "score": latest.get("verdicts", {}).get("overall", {}).get("score", 0),
                    "report_url": latest.get("result", ""),
                    "total_scans": data.get("total", 0),
                    "country": page.get("country", "Unknown"),
                    "server": page.get("server", "Unknown")
                }
            return {"malicious": False, "score": 0, "report_url": "No recent scans", "total_scans": 0}
        return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
