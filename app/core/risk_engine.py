def calculate_score(data: dict):
    score = 0
    breakdown = {}

    # Domain Age logic (Newer domains are riskier)
    da_score = 0
    da = data.get("domain_age", 3650)
    if da < 7:
        da_score = 50
    elif da < 30:
        da_score = 30
    elif da < 90:
        da_score = 15
    score += da_score
    if da_score > 0: breakdown["Domain Age"] = da_score

    # VirusTotal logic
    vt_score = 0
    vt_malicious = data.get("vt_malicious", 0)
    if vt_malicious > 5:
        vt_score = 40
    elif vt_malicious > 0:
        vt_score = 20
    score += vt_score
    if vt_score > 0: breakdown["VirusTotal"] = vt_score

    # Google Safe Browsing logic
    gsb_score = 0
    if data.get("phishing"):
        gsb_score = 100 # Immediate high risk
    score += gsb_score
    if gsb_score > 0: breakdown["Google Safe Browsing"] = gsb_score

    # URLScan logic
    url_score = 0
    urlscan = data.get("urlscan", {})
    if urlscan.get("malicious"):
        url_score = 30
    score += url_score
    if url_score > 0: breakdown["URLScan.io"] = url_score

    # AbuseIPDB logic
    abuse_score_val = 0
    abuseipdb = data.get("abuseipdb", {})
    abuse_confidence = abuseipdb.get("abuseConfidenceScore", 0)
    if abuse_confidence > 80:
        abuse_score_val = 40
    elif abuse_confidence > 40:
        abuse_score_val = 20
    score += abuse_score_val
    if abuse_score_val > 0: breakdown["AbuseIPDB"] = abuse_score_val

    # SSL Labs logic — poor grades indicate risk
    ssl_score = 0
    ssl = data.get("ssl_labs", {})
    if "error" not in ssl:
        grade = ssl.get("grade", "")
        if grade:
            g = grade.upper()
            if g.startswith("F") or g.startswith("T"):
                ssl_score += 25
            elif g.startswith("D"):
                ssl_score += 15
            elif g.startswith("C"):
                ssl_score += 8

        # Known vulnerabilities add risk
        vulns = ssl.get("vulnerabilities", {})
        if vulns.get("heartbleed"):
            ssl_score += 15
        if vulns.get("poodle_ssl3"):
            ssl_score += 10
        if vulns.get("drown_vulnerable"):
            ssl_score += 10
        if vulns.get("freak"):
            ssl_score += 10
            
    score += ssl_score
    if ssl_score > 0: breakdown["SSL Labs"] = ssl_score

    return min(score, 100), breakdown
