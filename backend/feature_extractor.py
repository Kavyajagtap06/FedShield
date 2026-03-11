import re
import requests
import socket
import whois
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import datetime


def extract_features(url):

    features = []
    reasons = []

    if not url.startswith("http"):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc

    # 1. Having IP Address
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    if re.search(ip_pattern, url):
        features.append(1)
        reasons.append("URL uses IP address instead of domain name")
    else:
        features.append(-1)

    # 2. URL Length
    if len(url) > 75:
        features.append(1)
        reasons.append("URL is unusually long")
    else:
        features.append(-1)

    # 3. Shortening Service
    shortening = r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co"
    if re.search(shortening, url):
        features.append(1)
        reasons.append("URL uses shortening service")
    else:
        features.append(-1)

    # 4. @ Symbol
    if "@" in url:
        features.append(1)
        reasons.append("URL contains '@' symbol")
    else:
        features.append(-1)

    # 5. Double slash redirect
    if url.count("//") > 1:
        features.append(1)
        reasons.append("URL contains multiple '//' redirects")
    else:
        features.append(-1)

    # 6. Hyphen in domain
    if "-" in domain:
        features.append(1)
        reasons.append("Domain contains suspicious hyphen")
    else:
        features.append(-1)

    # 7. Too many subdomains
    if domain.count(".") > 2:
        features.append(1)
        reasons.append("Domain has too many subdomains")
    else:
        features.append(-1)

    # 8. HTTPS token in domain
    if "https" in domain.replace("https://", ""):
        features.append(1)
        reasons.append("Domain contains misleading 'https' token")
    else:
        features.append(-1)

    # 9. SSL
    if parsed.scheme != "https":
        features.append(1)
        reasons.append("Website does not use HTTPS")
    else:
        features.append(-1)

    # 10. Domain Age
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age_days = (datetime.datetime.now() - creation_date).days

        if age_days < 365:
            features.append(1)
            reasons.append("Domain age is less than 1 year")
        else:
            features.append(-1)

    except:
        features.append(-1)  # assume safe if unknown

    # DNS
    try:
        socket.gethostbyname(domain)
        features.append(-1)
    except:
        features.append(1)
        reasons.append("No valid DNS record found")

    # HTML Features
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        if soup.find("iframe"):
            features.append(1)
            reasons.append("Page contains iframe elements")
        else:
            features.append(-1)

        if "onmouseover" in response.text.lower():
            features.append(1)
            reasons.append("Page uses onmouseover events")
        else:
            features.append(-1)

        if "alert(" in response.text.lower():
            features.append(1)
            reasons.append("Page contains popup alerts")
        else:
            features.append(-1)

        links = soup.find_all("a", href=True)
        external_links = [
            link for link in links if domain not in link["href"]
        ]

        if len(links) > 0 and len(external_links) > len(links) / 2:
            features.append(1)
            reasons.append("High number of external links")
        else:
            features.append(-1)

    except:
        while len(features) < 16:
            features.append(1)

    while len(features) < 30:
        features.append(0)

    return features, reasons