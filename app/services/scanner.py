from datetime import datetime, timezone
from app.services.virustotal import check_virustotal
from app.services.google_safe import check_google_safe
from app.utils.whois_lookup import get_domain_age
from app.core.risk_engine import calculate_score
from app.core.policy_engine import decide_verdict
from app.services.urlscan_service import check_urlscan
from app.services.abuseipdb_service import check_abuseipdb
from app.db.mongo import collection
from app.cache.memory_cache import get_cache, set_cache


def scan_url_service(url: str):
    # 1. Check cache
    cached = get_cache(url)
    if cached:
        return cached

    # 2. Check DB
    try:
        db_result = collection.find_one({"url": url})
        if db_result:
            db_result["_id"] = str(db_result["_id"])
            set_cache(url, db_result)
            return db_result
    except Exception as e:
        print(f"DB search error: {e}")

    # 3. API Calls
    vt_data = check_virustotal(url)          # now returns rich dict
    phishing = check_google_safe(url)
    domain_age = get_domain_age(url)
    urlscan_data = check_urlscan(url)
    abuseipdb_data = check_abuseipdb(url)

    # Build the data block — keep legacy keys for risk engine compatibility
    data = {
        # Legacy keys (risk engine uses these)
        "vt_malicious": vt_data.get("malicious", 0),
        "phishing": phishing,
        "domain_age": domain_age,
        # Rich VirusTotal data
        "virustotal": vt_data,
        "urlscan": urlscan_data,
        "abuseipdb": abuseipdb_data,
    }

    score = calculate_score(data)
    verdict = decide_verdict(score)

    result = {
        "url": url,
        "score": score,
        "verdict": verdict,
        "data": data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # 4. Save to DB
    try:
        inserted = collection.insert_one(result.copy())
        result["_id"] = str(inserted.inserted_id)
    except Exception as e:
        print(f"Error saving to DB: {e}")

    # 5. Cache
    set_cache(url, result)
    return result
