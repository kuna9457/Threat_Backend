import socket
import whois
from datetime import datetime

# python-whois talks to WHOIS servers over raw sockets with no timeout param
# of its own — a slow/unresponsive registrar (seen taking 13s+ on some ccTLDs)
# would otherwise block indefinitely. This caps every socket the process
# opens that doesn't set its own timeout (requests/dnspython calls elsewhere
# already pass explicit timeouts, so they're unaffected).
socket.setdefaulttimeout(8)


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
