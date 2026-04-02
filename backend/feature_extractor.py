# backend/feature_extractor.py

import re
import requests
import socket
import whois
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import datetime
import warnings
import threading
import time
warnings.filterwarnings('ignore')

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Cache for DNS lookups
dns_cache = {}
whois_cache = {}
html_cache = {}

# Set global socket timeout
socket.setdefaulttimeout(8)

def extract_features(url, timeout=10):
    """
    Extract 30 UCI features from a URL with robust HTML fetching
    Returns: (features_list, reasons_list, url_reachable, page_content)
    """
    features = []
    reasons = []
    url_reachable = True
    page_content = ""  # Initialize empty page content
    
    # Track if we encountered any errors/timeouts
    has_timeout = False
    has_connection_error = False

    # Ensure URL has scheme
    if not url.startswith("http"):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc
    
    # Clean domain
    domain = domain.replace("www.", "")
    if ":" in domain:
        domain = domain.split(":")[0]

    # 1. Having IP Address
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    if re.search(ip_pattern, url):
        features.append(1)
        reasons.append("URL uses IP address")
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
        reasons.append("Domain contains hyphen")
    else:
        features.append(-1)

    # 7. Too many subdomains
    if domain.count(".") > 2:
        features.append(1)
        reasons.append("Too many subdomains")
    else:
        features.append(-1)

    # 8. HTTPS token in domain
    if "https" in domain.replace("https://", ""):
        features.append(1)
        reasons.append("Domain contains misleading 'https'")
    else:
        features.append(-1)

    # 9. SSL
    if parsed.scheme != "https":
        features.append(1)
        reasons.append("No HTTPS")
    else:
        features.append(-1)

    # 10. Domain Age (with timeout using cache)
    domain_age_days = None
    try:
        # Check cache first
        if domain in whois_cache:
            age_days = whois_cache[domain]
        else:
            # Fast WHOIS with timeout
            result = [None]
            
            def get_whois():
                try:
                    domain_info = whois.whois(domain)
                    creation_date = domain_info.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    if creation_date:
                        age_days = (datetime.datetime.now() - creation_date).days
                        result[0] = age_days
                except:
                    result[0] = None
            
            # Run WHOIS in thread with timeout
            thread = threading.Thread(target=get_whois)
            thread.daemon = True
            thread.start()
            thread.join(timeout=3)
            
            age_days = result[0]
            if age_days is not None:
                whois_cache[domain] = age_days
        
        if age_days is not None:
            domain_age_days = age_days
            if age_days < 365:
                features.append(1)
                reasons.append(f"New domain ({age_days} days)")
            else:
                features.append(-1)
        else:
            features.append(-1)
            
    except:
        features.append(-1)

    # 11. DNS Resolution (with cache)
    try:
        if domain in dns_cache:
            dns_cache[domain]
        else:
            socket.gethostbyname(domain)
            dns_cache[domain] = True
        features.append(-1)
    except:
        features.append(1)
        reasons.append("DNS resolution failed")
        dns_cache[domain] = False
        url_reachable = False

    # ============================================
    # ROBUST HTML FETCH - Handles Cloudflare, redirects, bot protection
    # ============================================
    
    response_text = ""
    html_fetched = False
    
    # Multiple user agents to bypass bot detection
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    ]
    
    # For well-known domains, skip HTML fetch to save time
    well_known = ['google.com', 'facebook.com', 'youtube.com', 'amazon.com', 
                  'microsoft.com', 'apple.com', 'github.com', 'stackoverflow.com',
                  'wikipedia.org', 'paypal.com', 'netflix.com', 'spotify.com',
                  'twitter.com', 'linkedin.com']
    
    if domain in well_known:
        # Skip HTML fetch for well-known domains
        for i in range(12, 22):
            features.append(-1)
        reasons.append("Skipped HTML fetch for well-known domain")
        url_reachable = True
    else:
        # Check cache first
        if url in html_cache:
            response_text = html_cache[url]
            html_fetched = True
            print(f"  📦 Using cached HTML for {domain}")
        else:
            # Try multiple user agents
            for user_agent in user_agents:
                try:
                    session = requests.Session()
                    session.headers.update({
                        'User-Agent': user_agent,
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Accept-Encoding': 'gzip, deflate, br',
                        'Connection': 'keep-alive',
                        'Upgrade-Insecure-Requests': '1',
                        'Cache-Control': 'max-age=0',
                        'DNT': '1'
                    })
                    
                    # GET request with longer timeout
                    response = session.get(
                        url, 
                        timeout=timeout,
                        allow_redirects=True,
                        verify=False
                    )
                    
                    if response.status_code == 200:
                        response_text = response.text[:100000]  # Get up to 100KB
                        html_cache[url] = response_text
                        html_fetched = True
                        print(f"  ✅ HTML fetched: {len(response_text)} bytes")
                        break
                    elif response.status_code in [301, 302, 307, 308]:
                        # Follow redirect
                        redirect_url = response.headers.get('Location', '')
                        if redirect_url:
                            print(f"  🔀 Redirected to: {redirect_url[:60]}")
                            # Handle relative redirects
                            if redirect_url.startswith('/'):
                                redirect_url = f"{parsed.scheme}://{domain}{redirect_url}"
                            response = session.get(redirect_url, timeout=timeout)
                            if response.status_code == 200:
                                response_text = response.text[:100000]
                                html_cache[url] = response_text
                                html_fetched = True
                                break
                    else:
                        print(f"  ⚠️ HTTP {response.status_code} for {user_agent[:30]}...")
                        
                except requests.exceptions.Timeout:
                    print(f"  ⏱️ Timeout with user agent: {user_agent[:30]}...")
                    has_timeout = True
                    continue
                except requests.exceptions.ConnectionError:
                    print(f"  🔌 Connection error with user agent: {user_agent[:30]}...")
                    has_connection_error = True
                    continue
                except Exception as e:
                    print(f"  ❌ Error: {e}")
                    continue
            
            # If still no content, try with a simple request without session
            if not html_fetched:
                try:
                    response = requests.get(
                        url,
                        timeout=timeout,
                        headers={'User-Agent': user_agents[0]},
                        allow_redirects=True,
                        verify=False
                    )
                    if response.status_code == 200:
                        response_text = response.text[:100000]
                        html_cache[url] = response_text
                        html_fetched = True
                        print(f"  ✅ HTML fetched (simple): {len(response_text)} bytes")
                except:
                    pass
        
        # Update reachability based on fetch result
        if not html_fetched:
            url_reachable = False
            reasons.append("Could not fetch page content")
        
        # Parse HTML if we got content
        soup = None
        if response_text:
            try:
                soup = BeautifulSoup(response_text, "html.parser")
                print(f"  📄 Parsed HTML, title: {soup.title.string[:50] if soup.title else 'None'}")
            except:
                pass
        
        # 12. Iframe
        if soup and soup.find("iframe"):
            features.append(1)
            reasons.append("Contains iframe")
        else:
            features.append(-1)

        # 13. Onmouseover
        if response_text and "onmouseover" in response_text.lower():
            features.append(1)
            reasons.append("Uses onmouseover")
        else:
            features.append(-1)

        # 14. Popup alerts
        if response_text and "alert(" in response_text.lower():
            features.append(1)
            reasons.append("Contains popup alerts")
        else:
            features.append(-1)

        # 15. External links ratio
        if soup:
            links = soup.find_all("a", href=True)
            external_links = [link for link in links if domain not in link.get("href", "")]
            
            if len(links) > 0 and len(external_links) > len(links) / 2:
                features.append(1)
                reasons.append("High external links")
            else:
                features.append(-1)
        else:
            features.append(-1)

        # 16. Hidden fields
        if soup and soup.find("input", {"type": "hidden"}):
            features.append(1)
            reasons.append("Contains hidden fields")
        else:
            features.append(-1)

        # 17. Password field
        if soup and soup.find("input", {"type": "password"}):
            features.append(1)
            reasons.append("Contains password field")
        else:
            features.append(-1)

        # 18. Title mismatch
        if soup and soup.title:
            title = soup.title.string or ""
            if domain not in title.lower():
                features.append(1)
                reasons.append("Domain not in title")
            else:
                features.append(-1)
        else:
            features.append(-1)

        # 19. Favicon
        if soup and soup.find("link", {"rel": "icon"}):
            features.append(-1)
        else:
            features.append(1)
            reasons.append("No favicon")

        # 20. Submit button count
        if soup:
            submit_buttons = soup.find_all("input", {"type": "submit"})
            if len(submit_buttons) > 2:
                features.append(1)
                reasons.append("Multiple submit buttons")
            else:
                features.append(-1)
        else:
            features.append(-1)

        # 21. External CSS
        if soup:
            external_css = soup.find_all("link", {"rel": "stylesheet"})
            if len(external_css) > 3:
                features.append(1)
                reasons.append("Multiple external CSS")
            else:
                features.append(-1)
        else:
            features.append(-1)

    # 22-30. Fill remaining features with defaults
    while len(features) < 30:
        features.append(-1)
    
    # Ensure exactly 30 features
    if len(features) > 30:
        features = features[:30]
    
    # Store page content for content analysis
    page_content = response_text[:20000] if response_text else ""  # Store up to 20KB
    
    # Add a final reachability flag to reasons
    if not url_reachable:
        reasons.append("URL appears unreachable")
    
    # Return 4 values: features, reasons, url_reachable, page_content
    return features, reasons, url_reachable, page_content