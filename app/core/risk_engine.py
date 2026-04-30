def calculate_score(data: dict):
    score = 0

    # Domain Age logic (Newer domains are riskier)
    if data.get("domain_age", 3650) < 7:
        score += 50
    elif data.get("domain_age", 3650) < 30:
        score += 30
    elif data.get("domain_age", 3650) < 90:
        score += 15

    # VirusTotal logic
    vt_malicious = data.get("vt_malicious", 0)
    if vt_malicious > 5:
        score += 40
    elif vt_malicious > 0:
        score += 20

    # Google Safe Browsing logic
    if data.get("phishing"):
        score += 100 # Immediate high risk

    # URLScan logic
    urlscan = data.get("urlscan", {})
    if urlscan.get("malicious"):
        score += 30

    # AbuseIPDB logic
    abuseipdb = data.get("abuseipdb", {})
    abuse_score = abuseipdb.get("abuseConfidenceScore", 0)
    if abuse_score > 80:
        score += 40
    elif abuse_score > 40:
        score += 20

    return min(score, 100)
