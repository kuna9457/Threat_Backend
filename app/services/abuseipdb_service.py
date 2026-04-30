import socket
import requests
from urllib.parse import urlparse
from app.config import settings

def check_abuseipdb(url: str):
    if not settings.abuseipdb_api_key:
        return {"error": "No API key configured"}

    # Normalise: bare domains like 'welthwest.com' have no scheme,
    # so urlparse puts everything in 'path', not 'netloc'.
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    domain = urlparse(url).netloc.split(':')[0]
    if not domain:
        return {"error": "Invalid URL format"}
    
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return {"error": "Could not resolve domain to IP"}

    headers = {
        "Key": settings.abuseipdb_api_key,
        "Accept": "application/json"
    }
    
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "ip": ip,
                "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                "totalReports": data.get("totalReports", 0),
                "usageType": data.get("usageType", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "countryCode": data.get("countryCode", "Unknown")
            }
        return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
