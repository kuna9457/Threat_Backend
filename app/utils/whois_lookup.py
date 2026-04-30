import whois
from datetime import datetime

def get_domain_age(url: str):
    """
    Returns domain age in days.
    If age cannot be determined, returns a default high age (stable) for safety in this demo.
    """
    try:
        domain = url.split("//")[-1].split("/")[0]
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            age = (datetime.now() - creation_date).days
            return age
        return 3650 # Default 10 years if unknown
    except Exception:
        return 3650 
