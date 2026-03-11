import requests
import dns.resolver
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse


def get_domain_intelligence(url):

    results = {
        "domain_age_days": None,
        "registrar": "Unknown",
        "name_servers": [],
        "ssl_age_days": None
    }

    try:
        parsed = urlparse(url)

        domain = parsed.netloc if parsed.netloc else parsed.path
        domain = domain.replace("www.", "").strip()

        # =========================
        # DOMAIN AGE (RDAP + WHOIS fallback)
        # =========================

        try:
            rdap_url = f"https://rdap.org/domain/{domain}"
            r = requests.get(rdap_url, timeout=6)

            if r.status_code == 200:
                data = r.json()

                events = data.get("events", [])

                for event in events:
                    action = event.get("eventAction", "").lower()

                    if action in ["registration", "registered"]:
                        creation = event.get("eventDate")

                        if creation:
                            creation = creation.replace("Z", "")
                            creation_date = datetime.fromisoformat(creation)

                            results["domain_age_days"] = (datetime.utcnow() - creation_date).days
                            break

        except:
            pass


        # =========================
        # WHOIS fallback (if RDAP failed)
        # =========================

        if results["domain_age_days"] is None:

            try:
                import whois

                w = whois.whois(domain)

                creation = w.creation_date

                if isinstance(creation, list):
                    creation = creation[0]

                if creation:
                    creation = creation.replace(tzinfo=None)
                    age_days = (datetime.utcnow() - creation).days
                    results["domain_age_days"] = age_days

                if w.registrar:
                    results["registrar"] = w.registrar

            except Exception as e:
                print("WHOIS fallback error:", e)
                
        # =========================
        # DNS Name Servers
        # =========================
        try:
            answers = dns.resolver.resolve(domain, "NS")
            results["name_servers"] = [str(ns) for ns in answers]
        except Exception as e:
            print("DNS error:", e)

        # =========================
        # SSL Certificate Age
        # =========================
        try:
            context = ssl.create_default_context()

            with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))

                cert = s.getpeercert()

                not_before = cert["notBefore"]

                cert_date = datetime.strptime(
                    not_before,
                    "%b %d %H:%M:%S %Y %Z"
                )

                results["ssl_age_days"] = (datetime.utcnow() - cert_date).days

        except Exception as e:
            print("SSL error:", e)

    except Exception as e:
        print("Domain intelligence error:", e)

    return results