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

    # SSL Labs logic — poor grades indicate risk
    ssl = data.get("ssl_labs", {})
    if "error" not in ssl:
        grade = ssl.get("grade", "")
        if grade:
            g = grade.upper()
            if g.startswith("F") or g.startswith("T"):
                score += 25
            elif g.startswith("D"):
                score += 15
            elif g.startswith("C"):
                score += 8

        # Known vulnerabilities add risk
        vulns = ssl.get("vulnerabilities", {})
        if vulns.get("heartbleed"):
            score += 15
        if vulns.get("poodle_ssl3"):
            score += 10
        if vulns.get("drown_vulnerable"):
            score += 10
        if vulns.get("freak"):
            score += 10

    # MX Tools — poor mail security is a weak signal
    mx = data.get("mx_tools", {})
    if "error" not in mx:
        mail_sec = mx.get("mail_security", {})
        mail_score = mail_sec.get("score", 100)
        if mail_score < 25:
            score += 5  # weak signal

    return min(score, 100)
