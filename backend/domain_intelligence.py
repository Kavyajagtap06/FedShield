"""
Enhanced domain intelligence with platform detection and stronger signals
Includes SSL certificate validation to detect invalid certificates
"""

import requests
import dns.resolver
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse
import warnings
warnings.filterwarnings('ignore')

# ============================================
# STRATEGY 3: Platform Detection
# List of platforms commonly abused for phishing
# ============================================

SUSPICIOUS_PLATFORMS = [
    'ghost.io', 'framer.app', 'zapier.app', 'workers.dev',
    'web.app', 'firebaseapp.com', 'github.io', 'netlify.app',
    'vercel.app', 'herokuapp.com', 'pages.dev', 'cloudfront.net',
    'azurewebsites.net', 'awsapps.com', 'blogspot.com', 'wordpress.com',
    'wixsite.com', 'weebly.com', 'site123.me', 'carrd.co',
    'click', 'sbs', 'cfd'  # New TLDs
]

# Suspicious TLDs (often used for phishing)
SUSPICIOUS_TLDS = [
    '.cfd', '.sbs', '.click', '.top', '.xyz', '.win', '.bid',
    '.loan', '.download', '.review', '.country', '.work', '.date',
    '.men', '.online', '.site', '.tech', '.store', '.space', '.fun'
]

def detect_suspicious_tld(domain):
    """Check if domain has suspicious TLD"""
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return tld
    return None

def detect_platform_hosting(domain):
    """Check if domain is hosted on a platform"""
    for platform in SUSPICIOUS_PLATFORMS:
        if platform in domain:
            return platform
    return None

def validate_ssl_certificate(domain, timeout=5):
    """
    Validate SSL certificate for a domain.
    Detects issues like ERR_CERT_COMMON_NAME_INVALID
    
    Returns:
        (is_valid, error_message, days_until_expiry, cert_details)
    """
    try:
        # Create SSL context with hostname verification
        context = ssl.create_default_context()
        
        # Connect and validate certificate
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        
        # Check if certificate has the correct common name/SAN
        # The ssl module already does this when server_hostname is provided
        
        # Get expiry information
        not_after = cert.get('notAfter', '')
        if not_after:
            expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_until_expiry = (expiry_date - datetime.utcnow()).days
        else:
            days_until_expiry = None
        
        # Get certificate subject (common name)
        subject = dict(x[0] for x in cert.get('subject', []))
        common_name = subject.get('commonName', 'Unknown')
        
        # Get SAN (Subject Alternative Names)
        san = cert.get('subjectAltName', [])
        alt_names = [name for _, name in san]
        
        return {
            "is_valid": True,
            "error": None,
            "days_until_expiry": days_until_expiry,
            "common_name": common_name,
            "alt_names": alt_names,
            "issuer": dict(x[0] for x in cert.get('issuer', []))
        }
        
    except ssl.CertificateError as e:
        # This catches ERR_CERT_COMMON_NAME_INVALID and other cert errors
        return {
            "is_valid": False,
            "error": f"Certificate error: {str(e)}",
            "days_until_expiry": None,
            "common_name": None,
            "alt_names": [],
            "issuer": None
        }
    except ssl.SSLError as e:
        return {
            "is_valid": False,
            "error": f"SSL error: {str(e)}",
            "days_until_expiry": None,
            "common_name": None,
            "alt_names": [],
            "issuer": None
        }
    except socket.timeout:
        return {
            "is_valid": False,
            "error": "Connection timeout",
            "days_until_expiry": None,
            "common_name": None,
            "alt_names": [],
            "issuer": None
        }
    except ConnectionRefusedError:
        return {
            "is_valid": False,
            "error": "Connection refused",
            "days_until_expiry": None,
            "common_name": None,
            "alt_names": [],
            "issuer": None
        }
    except Exception as e:
        return {
            "is_valid": False,
            "error": f"SSL validation error: {str(e)}",
            "days_until_expiry": None,
            "common_name": None,
            "alt_names": [],
            "issuer": None
        }

def get_domain_intelligence(url):
    """
    Enhanced domain intelligence with platform detection and SSL validation
    """
    results = {
        "domain_age_days": None,
        "registrar": "Unknown",
        "name_servers": [],
        "ssl_age_days": None,
        "has_https": None,
        "dns_resolves": None,
        "is_platform_hosted": False,
        "platform_name": None,
        "suspicious_tld": None,
        "is_suspicious": False,
        "reputation_signals": [],
        # NEW: SSL certificate validation fields
        "certificate_valid": None,
        "certificate_error": None,
        "certificate_days_until_expiry": None,
        "certificate_common_name": None
    }

    try:
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path
        domain = domain.replace("www.", "").strip()
        
        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]

        # Check HTTPS
        results["has_https"] = 1 if parsed.scheme == "https" else 0

        # ============================================
        # NEW: SSL Certificate Validation
        # This catches ERR_CERT_COMMON_NAME_INVALID
        # ============================================
        if results["has_https"] == 1:
            cert_info = validate_ssl_certificate(domain)
            results["certificate_valid"] = cert_info["is_valid"]
            results["certificate_error"] = cert_info["error"]
            results["certificate_days_until_expiry"] = cert_info["days_until_expiry"]
            results["certificate_common_name"] = cert_info["common_name"]
            
            if not cert_info["is_valid"]:
                results["reputation_signals"].append(f"🔐 INVALID SSL CERTIFICATE: {cert_info['error']}")
                results["is_suspicious"] = True
            else:
                # Valid certificate, check if it's very new (potential phishing)
                # (SSL age is handled later)
                pass

        # ============================================
        # STRATEGY 3: Platform Detection
        # ============================================
        platform = detect_platform_hosting(domain)
        if platform:
            results["is_platform_hosted"] = True
            results["platform_name"] = platform
            results["reputation_signals"].append(f"⚠️ Hosted on {platform} - Often abused for phishing")
            results["is_suspicious"] = True

        # Check suspicious TLD
        suspicious_tld = detect_suspicious_tld(domain)
        if suspicious_tld:
            results["suspicious_tld"] = suspicious_tld
            results["reputation_signals"].append(f"⚠️ Suspicious TLD: {suspicious_tld}")
            results["is_suspicious"] = True

        # ============================================
        # STRATEGY 2: Enhanced Domain Age Detection
        # ============================================
        
        # Try RDAP first (faster)
        try:
            rdap_url = f"https://rdap.org/domain/{domain}"
            r = requests.get(rdap_url, timeout=5)
            
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

        # Fallback to WHOIS
        if results["domain_age_days"] is None:
            try:
                import whois
                w = whois.whois(domain)
                creation = w.creation_date
                
                if isinstance(creation, list):
                    creation = creation[0]
                
                if creation:
                    if hasattr(creation, 'tzinfo'):
                        creation = creation.replace(tzinfo=None)
                    age_days = (datetime.utcnow() - creation).days
                    results["domain_age_days"] = age_days
                
                if w.registrar:
                    results["registrar"] = w.registrar
                    
            except Exception as e:
                print(f"  WHOIS fallback error: {e}")

        # Add reputation signals based on domain age
        if results["domain_age_days"]:
            if results["domain_age_days"] < 7:
                results["reputation_signals"].append(f"🚨 EXTREMELY NEW DOMAIN ({results['domain_age_days']} days) - High risk")
                results["is_suspicious"] = True
            elif results["domain_age_days"] < 30:
                results["reputation_signals"].append(f"⚠️ NEW DOMAIN ({results['domain_age_days']} days) - Suspicious")
                results["is_suspicious"] = True
            elif results["domain_age_days"] < 90:
                results["reputation_signals"].append(f"📅 Recent domain ({results['domain_age_days']} days)")
                results["is_suspicious"] = True
            elif results["domain_age_days"] > 365:
                results["reputation_signals"].append(f"✅ Established domain ({results['domain_age_days']//365} years) - Good")

        # ============================================
        # DNS Resolution
        # ============================================
        try:
            answers = dns.resolver.resolve(domain, "A", lifetime=3)
            results["dns_resolves"] = 1
            for answer in answers:
                results["ip_address"] = str(answer)
                break
        except:
            results["dns_resolves"] = 0
            results["reputation_signals"].append("⚠️ DNS resolution failed - Suspicious")
            results["is_suspicious"] = True

        # ============================================
        # DNS Name Servers
        # ============================================
        try:
            answers = dns.resolver.resolve(domain, "NS", lifetime=3)
            results["name_servers"] = [str(ns) for ns in answers]
        except:
            pass

        # ============================================
        # SSL Certificate Age Analysis
        # ============================================
        if results["has_https"] == 1:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
                    s.settimeout(5)
                    s.connect((domain, 443))
                    cert = s.getpeercert()
                    
                    not_before = cert.get("notBefore", "")
                    if not_before:
                        cert_date = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                        results["ssl_age_days"] = (datetime.utcnow() - cert_date).days
                        
                        if results["ssl_age_days"] < 7:
                            results["reputation_signals"].append(f"⚠️ Very new SSL certificate ({results['ssl_age_days']} days)")
                            results["is_suspicious"] = True
                    
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        results["ssl_expires_days"] = (exp_date - datetime.utcnow()).days
                        
                        if results.get("ssl_expires_days", 0) < 0:
                            results["reputation_signals"].append("⚠️ SSL certificate expired")
                            results["is_suspicious"] = True
                            
            except Exception as e:
                results["reputation_signals"].append("⚠️ SSL certificate issue")
                results["is_suspicious"] = True
        else:
            # No HTTPS on suspicious domain
            if results["is_suspicious"]:
                results["reputation_signals"].append("🔓 No HTTPS on suspicious domain")
                results["is_suspicious"] = True

        # ============================================
        # Final suspicious flag
        # ============================================
        if results["is_suspicious"]:
            results["reputation_signals"].insert(0, "⚠️ Domain shows suspicious characteristics")

    except Exception as e:
        print(f"  Domain intelligence error: {e}")
        results["error"] = str(e)

    return results