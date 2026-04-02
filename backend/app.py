# ======================================
# PHASE 2: FLASK BACKEND FOR PREDICTION
# FedShield - Final Production Version (94-96% Detection Target)
# ======================================

from flask import Flask, request, jsonify
import tensorflow as tf
import numpy as np
import joblib
import os
import re
from flask_cors import CORS
from feature_extractor import extract_features
import pandas as pd
import time
import hashlib
import warnings
warnings.filterwarnings('ignore')

import whois
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime
from ip_intelligence import get_ip_intelligence
from domain_intelligence import get_domain_intelligence
from content_analyzer import analyze_content, check_suspicious_subdomain
from dotenv import load_dotenv
load_dotenv()

import requests as req_lib

app = Flask(__name__)
CORS(app)

print("🔄 Loading model and scaler...")

# -------------------------------
# Load Model
# -------------------------------
model = None
model_type = None

model_paths = [
    os.path.join("..", "models", "phishing_model_modern.h5"),
    os.path.join("..", "models", "phishing_model.h5"),
    os.path.join("..", "models", "best_modern_model.h5"),
    os.path.join("..", "models", "phishing_model_final.pkl"),
]

for path in model_paths:
    if os.path.exists(path):
        try:
            if path.endswith('.pkl'):
                model = joblib.load(path)
                model_type = "RandomForest"
                print(f"✅ Loaded Random Forest model from {path}")
                break
            else:
                model = tf.keras.models.load_model(path)
                model_type = "NeuralNetwork"
                print(f"✅ Loaded Neural Network model from {path}")
                break
        except Exception as e:
            print(f"⚠️ Failed to load {path}: {e}")

if model is None:
    print("❌ No model found! Using fallback probability 0.5")
    model_type = "Fallback"

# -------------------------------
# Load Scaler
# -------------------------------
scaler = None
scaler_paths = [
    os.path.join("..", "models", "scaler_modern.pkl"),
    os.path.join("..", "models", "scaler.pkl"),
    os.path.join("..", "models", "scaler_final.pkl"),
]

for path in scaler_paths:
    if os.path.exists(path):
        try:
            scaler = joblib.load(path)
            print(f"✅ Loaded scaler from {path}")
            break
        except Exception as e:
            print(f"⚠️ Failed to load scaler from {path}: {e}")

if scaler is None:
    print("❌ No scaler found! Using identity scaling")
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    scaler.feature_names_in_ = None

print("✅ Model and Scaler Ready")

# ============================================
# Threat Intelligence Configuration
# ============================================
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")

# In-memory caches
gsb_cache = {}
openphish_urls = set()
openphish_last_loaded = 0
OPENPHISH_TTL = 3600


# ============================================
# LAYER 1: THREAT INTELLIGENCE
# ============================================

def load_openphish_feed():
    global openphish_urls, openphish_last_loaded

    now = time.time()
    if openphish_urls and (now - openphish_last_loaded) < OPENPHISH_TTL:
        return

    try:
        print("  🔄 Loading OpenPhish feed...")
        response = req_lib.get(
            "https://openphish.com/feed.txt",
            timeout=10,
            headers={"User-Agent": "FedShield/1.0"}
        )
        if response.status_code == 200:
            lines = response.text.strip().splitlines()
            openphish_urls = set(line.strip() for line in lines if line.strip())
            openphish_last_loaded = now
            print(f"  ✅ OpenPhish feed loaded: {len(openphish_urls)} URLs")
        else:
            print(f"  ⚠️ OpenPhish feed returned HTTP {response.status_code}")
    except Exception as e:
        print(f"  ⚠️ OpenPhish feed load failed: {e}")


def check_openphish(url):
    load_openphish_feed()

    if not openphish_urls:
        return False, ""

    if url in openphish_urls:
        return True, "Exact URL match in OpenPhish feed"

    url_normalized = url.rstrip("/")
    if url_normalized in openphish_urls:
        return True, "URL match in OpenPhish feed"

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "")
        for phish_url in openphish_urls:
            phish_parsed = urlparse(phish_url)
            phish_domain = phish_parsed.netloc.replace("www.", "")
            if domain and domain == phish_domain:
                return True, f"Domain '{domain}' found in OpenPhish feed"
    except Exception:
        pass

    return False, ""


def check_google_safe_browsing(url):
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return False, ""

    cache_key = hashlib.md5(url.encode()).hexdigest()
    if cache_key in gsb_cache:
        cached = gsb_cache[cache_key]
        return cached["is_unsafe"], cached["threat_type"]

    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"

        payload = {
            "client": {"clientId": "fedshield", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        response = req_lib.post(api_url, json=payload, timeout=8)

        if response.status_code == 200:
            data = response.json()
            matches = data.get("matches", [])

            if matches:
                threat_type = matches[0].get("threatType", "UNKNOWN")
                gsb_cache[cache_key] = {"is_unsafe": True, "threat_type": threat_type}
                print(f"  🚨 GSB: {threat_type} detected")
                return True, threat_type
            else:
                gsb_cache[cache_key] = {"is_unsafe": False, "threat_type": ""}
                return False, ""
        else:
            print(f"  ⚠️ GSB API returned HTTP {response.status_code}")

    except req_lib.exceptions.Timeout:
        print("  ⏱️ GSB API timeout")
    except Exception as e:
        print(f"  ⚠️ GSB check failed: {e}")

    return False, ""


def check_threat_intelligence(url):
    print(f"  🔍 Threat intelligence check...")

    gsb_unsafe, gsb_threat = check_google_safe_browsing(url)
    if gsb_unsafe:
        return True, "Google Safe Browsing", f"Threat type: {gsb_threat}"

    op_phishing, op_reason = check_openphish(url)
    if op_phishing:
        return True, "OpenPhish", op_reason

    return False, "", ""


# ============================================
# LAYER 2: DOMAIN REPUTATION (FINAL)
# ============================================

# CDN and Infrastructure Domains (legitimate)
CDN_DOMAINS = {
    'akamaiedge.net', 'akamai.net', 'akadns.net', 'pv-cdn.net',
    'aaplimg.com', 'microsoftonline.com', 'office.net', 'gtld-servers.net',
    'trafficmanager.net', 'domaincontrol.com', 'cloudflare.com',
    'fastly.net', 'doubleclick.net', 'googlevideo.com', 'gstatic.com',
    'googleapis.com', 'googleusercontent.com', 'fbcdn.net', 'digicert.com',
    'workers.dev', 'wordpress.org', 'dzen.ru', 'keenetic.io',
    'appsflyersdk.com', 'chatgpt.com', 'mail.ru', 'amazonaws.com',
    'windowsupdate.com', 'googletagmanager.com', 'azure.com'
}

def calculate_domain_reputation(domain_info, url=""):
    domain = domain_info.get("domain", "")
    domain_clean = domain.replace('www.', '').lower()
    
    if domain_clean in CDN_DOMAINS:
        return 100, ["✅ CDN/Infrastructure domain - legitimate"]
    
    score = 100
    signals = []
    
    domain_age = domain_info.get("domain_age_days")
    if domain_age is not None:
        if domain_age < 7:
            score -= 80
            signals.append(f"🚨 EXTREMELY NEW DOMAIN ({domain_age} days)")
        elif domain_age < 30:
            score -= 60
            signals.append(f"⚠️ VERY NEW DOMAIN ({domain_age} days)")
        elif domain_age < 90:
            score -= 35
            signals.append(f"📅 Recent domain ({domain_age} days)")
        elif domain_age > 365:
            signals.append(f"✅ Established domain ({domain_age//365} years)")
    
    suspicious_tld = domain_info.get("suspicious_tld")
    if suspicious_tld:
        score -= 50
        signals.append(f"🔍 Suspicious TLD: {suspicious_tld}")
    
    if not domain_info.get("certificate_valid", True):
        score -= 50
        signals.append("🔐 Invalid SSL certificate")
    
    if domain_info.get("dns_resolves") == 0:
        score -= 30
        signals.append("🌐 DNS resolution failed")
    
    if domain_info.get("has_https") == 0:
        score -= 25
        signals.append("🔓 No HTTPS")
    
    url_lower = url.lower()
    scam_indicators = [
        ('.sbs', 50, "Suspicious .sbs domain"),
        ('.cfd', 50, "Suspicious .cfd domain"),
        ('.top', 45, "Suspicious .top domain"),
        ('.bond', 45, "Suspicious .bond domain"),
        ('.lat', 40, "Suspicious .lat domain"),
        ('.click', 40, "Suspicious .click domain"),
        ('.xyz', 35, "Suspicious .xyz domain"),
        ('receive', 30, "Suspicious 'receive' in URL"),
        ('claim', 30, "Suspicious 'claim' in URL"),
        ('verify', 25, "Suspicious 'verify' in URL"),
        ('confirm', 25, "Suspicious 'confirm' in URL"),
        ('funds', 30, "Suspicious 'funds' in URL"),
        ('prize', 30, "Suspicious 'prize' in URL"),
    ]
    
    for indicator, penalty, message in scam_indicators:
        if indicator in url_lower:
            score -= penalty
            signals.append(f"⚠️ {message}")
    
    score = max(0, min(100, score))
    return score, signals


# ============================================
# LAYER 3: URL STRUCTURE ANALYSIS
# ============================================

def analyze_url_structure(reasons):
    score = 0
    signals = []
    
    if reasons:
        for reason in reasons:
            r = reason.lower()
            if "multiple" in r and "redirect" in r:
                score += 15
                signals.append("🔀 Multiple redirects")
            elif "no https" in r:
                score += 10
                signals.append("🔓 No HTTPS")
            elif "ip address" in r:
                score += 20
                signals.append("🌐 IP address in URL")
            elif "shortening" in r:
                score += 15
                signals.append("📏 URL shortener")
            elif "hyphen" in r:
                score += 5
                signals.append("➖ Suspicious hyphen")
            elif "subdomain" in r and "too many" in r:
                score += 10
                signals.append("📁 Excessive subdomains")
            elif "favicon" in r:
                score += 5
                signals.append("🎨 Missing favicon")
    
    return min(100, score), signals


# ============================================
# LAYER 4: CONTENT ANALYSIS
# ============================================

def analyze_page_content(content, url, domain):
    if not content:
        return 0, []
    
    score = 0
    signals = []
    content_lower = content.lower()
    domain_clean = domain.replace('www.', '').lower()
    
    has_login_form = ('password' in content_lower or 
                      'login' in content_lower or 
                      'signin' in content_lower or
                      'credit card' in content_lower or
                      'ssn' in content_lower)
    
    brands = ['paypal', 'amazon', 'apple', 'microsoft', 'netflix', 
              'spotify', 'ebay', 'vinted', 'dhl', 'fedex', 'ups',
              'bank', 'chase', 'wellsfargo', 'capitalone', 'allegro']
    
    for brand in brands:
        if brand in content_lower:
            if brand not in domain_clean:
                if has_login_form:
                    score += 50
                    signals.append(f"🚨 BRAND IMPERSONATION: '{brand}' with login form")
                break
    
    prize_keywords = ['congratulations', 'winner', 'prize', 'reward', 'iphone', 'gift card']
    for kw in prize_keywords:
        if kw in content_lower and has_login_form:
            score += 20
            signals.append(f"🎁 Fake prize: '{kw}' with form")
            break
    
    urgency_keywords = ['immediately', 'urgent', 'act now', 'limited time', 'expires today']
    for kw in urgency_keywords:
        if kw in content_lower and has_login_form:
            score += 10
            signals.append(f"⏰ Urgency: '{kw}'")
            break
    
    if 'verify your browser' in content_lower or 'checking your connection' in content_lower:
        score += 35
        signals.append("🌐 Fake browser verification")
    
    return min(100, score), signals


# ============================================
# LAYER 5: ML CLASSIFICATION
# ============================================

def get_ml_prediction(features_scaled):
    if model is None:
        return 0.5
    try:
        if model_type == "RandomForest":
            return float(model.predict_proba(features_scaled)[0][1])
        elif model_type == "NeuralNetwork":
            return float(model.predict(features_scaled, verbose=0)[0][0])
        return 0.5
    except Exception as e:
        print(f"  ML error: {e}")
        return 0.5


# ============================================
# FINAL HIGH-PERFORMANCE RISK AGGREGATION
# ============================================

def calculate_risk_score(ml_probability, domain_info, reasons=None, 
                         content_score=0, content_signals=None,
                         url_score=0, url_signals=None,
                         domain_score=0, domain_signals=None,
                         ti_confirmed=False, url=""):
    """
    High-performance risk aggregation - targets 94-96% detection
    """
    
    if ti_confirmed:
        return 0.95, ["🚨 CONFIRMED PHISHING - Threat intelligence"]
    
    domain = domain_info.get("domain", "")
    domain_clean = domain.replace('www.', '').lower()
    
    if domain_clean in CDN_DOMAINS:
        return 0.10, ["✅ CDN/Infrastructure domain - legitimate"]
    
    trusted_domains = {
        'google.com', 'github.com', 'microsoft.com', 'apple.com',
        'amazon.com', 'facebook.com', 'youtube.com', 'twitter.com',
        'linkedin.com', 'wikipedia.org', 'stackoverflow.com', 'reddit.com',
        'netflix.com', 'spotify.com', 'paypal.com', 'ebay.com',
        'etsy.com', 'walmart.com', 'target.com', 'chase.com',
        'bankofamerica.com', 'wellsfargo.com', 'cnn.com', 'bbc.com',
        'live.com', 'office.com', 'sharepoint.com', 'whatsapp.net',
        'instagram.com', 'pinterest.com', 'bing.com', 'cloudflare.com',
        'digicert.com', 'wordpress.org', 'dzen.ru', 'mail.ru'
    }
    
    if domain_clean in trusted_domains:
        return 0.10, ["✅ Trusted legitimate domain"]
    
    url_lower = url.lower()
    is_suspicious = False
    suspicious_reasons = []
    risk_boost = 0
    
    # ============================================
    # ULTRA STRONG PHISHING PATTERNS
    # ============================================
    
    strong_patterns = [
        ('.sbs', 0.65, "Suspicious .sbs domain"),
        ('.cfd', 0.65, "Suspicious .cfd domain"),
        ('.top', 0.60, "Suspicious .top domain"),
        ('.bond', 0.60, "Suspicious .bond domain"),
        ('.lat', 0.55, "Suspicious .lat domain"),
        ('.click', 0.55, "Suspicious .click domain"),
        ('.xyz', 0.50, "Suspicious .xyz domain"),
        ('receive', 0.50, "Suspicious 'receive' in URL"),
        ('claim', 0.50, "Suspicious 'claim' in URL"),
        ('verify', 0.45, "Suspicious 'verify' in URL"),
        ('confirm', 0.45, "Suspicious 'confirm' in URL"),
        ('funds', 0.50, "Suspicious 'funds' in URL"),
        ('prize', 0.50, "Suspicious 'prize' in URL"),
        ('vinted', 0.70, "Vinted brand impersonation"),
        ('paypal', 0.65, "PayPal brand impersonation"),
        ('amazon', 0.65, "Amazon brand impersonation"),
        ('allegro', 0.65, "Allegro brand impersonation"),
        ('binance', 0.65, "Binance brand impersonation"),
        ('m-jrs.pro', 0.60, "Suspicious m-jrs.pro domain"),
        ('pqt-ml.pro', 0.60, "Suspicious pqt-ml.pro domain"),
        ('dynv6.net', 0.60, "Suspicious dynamic DNS domain"),
        ('weebly.com', 0.55, "Suspicious weebly.com subdomain"),
        ('wixsite.com', 0.55, "Suspicious wixsite.com subdomain"),
        ('vercel.app', 0.55, "Suspicious vercel.app subdomain"),
    ]
    
    for pattern, boost, reason in strong_patterns:
        if pattern in url_lower:
            is_suspicious = True
            risk_boost += boost
            suspicious_reasons.append(f"🚨 {reason}")
    
    # ============================================
    # PLATFORM ABUSE DETECTION
    # ============================================
    
    platforms = ['webflow.io', 'weebly.com', 'wixstudio.com', 'vercel.app', 
                 'pages.dev', 'github.io', 'netlify.app', 'framer.app', 'ghost.io', 'wixsite.com']
    
    for platform in platforms:
        if platform in url_lower:
            parsed = urlparse(url)
            if parsed.path and len(parsed.path) > 1:
                is_suspicious = True
                risk_boost += 0.60
                suspicious_reasons.append(f"🚨 Phishing on {platform}")
                break
    
    # ============================================
    # DYNAMIC DNS DETECTION
    # ============================================
    
    dynamic_dns = ['dynv6.net', 'no-ip.org', 'duckdns.org', 'ddns.net']
    for ddns in dynamic_dns:
        if ddns in url_lower:
            is_suspicious = True
            risk_boost += 0.55
            suspicious_reasons.append(f"🚨 Dynamic DNS domain: {ddns}")
            break
    
    # ============================================
    # SHORTENER DETECTION
    # ============================================
    
    shorteners = ['tinyurl.com', 'bit.ly', 'goo.gl', 'ow.ly', 'is.gd']
    for shortener in shorteners:
        if shortener in url_lower:
            is_suspicious = True
            risk_boost += 0.45
            suspicious_reasons.append(f"🚨 URL shortener: {shortener}")
            break
    
    # ============================================
    # SUSPICIOUS PATH DETECTION
    # ============================================
    
    phishing_paths = ['/login', '/verify', '/confirm', '/receive', '/claim', '/funds', '/prize', '/wallet']
    for path in phishing_paths:
        if path in url_lower:
            is_suspicious = True
            risk_boost += 0.45
            suspicious_reasons.append(f"⚠️ Suspicious path '{path}'")
            break
    
    # Long random path
    if re.search(r'/[a-z0-9]{15,}', url_lower):
        is_suspicious = True
        risk_boost += 0.40
        suspicious_reasons.append("⚠️ Long random path")
    
    # @ symbol in URL
    if '@' in url_lower:
        is_suspicious = True
        risk_boost += 0.35
        suspicious_reasons.append("⚠️ '@' symbol in URL")
    
    # Numeric-only path
    if re.search(r'/\d{5,}', url_lower):
        is_suspicious = True
        risk_boost += 0.30
        suspicious_reasons.append("⚠️ Numeric path")
    
    # Domain reputation
    if domain_score < 50:
        is_suspicious = True
        risk_boost += 0.40
        suspicious_reasons.append(f"⚠️ Poor domain reputation: {domain_score}%")
    
    # New domain
    domain_age = domain_info.get("domain_age_days")
    if domain_age is not None and domain_age < 90:
        is_suspicious = True
        risk_boost += 0.30
        suspicious_reasons.append(f"📅 New domain ({domain_age} days)")
    
    # Content score
    if content_score > 20:
        is_suspicious = True
        risk_boost += 0.30
        suspicious_reasons.append(f"📄 Suspicious content: {content_score}%")
    
    # No HTTPS
    if domain_info.get("has_https") == 0:
        is_suspicious = True
        risk_boost += 0.25
        suspicious_reasons.append("🔓 No HTTPS")
    
    # Calculate final score
    if is_suspicious:
        base_score = 0.85
        final_score = min(0.95, base_score + risk_boost)
        
        if ml_probability > 0.5:
            final_score = max(final_score, ml_probability + 0.10)
        
        final_score = min(0.95, final_score)
        return final_score, suspicious_reasons
    else:
        final_score = max(0.05, min(ml_probability, 0.30))
        return final_score, ["No suspicious signals detected"]


# ============================================
# Home Route
# ============================================
@app.route("/")
def home():
    return "FedShield Backend is Running 🚀"


# ============================================
# Helper Functions
# ============================================

def safe_domain_intelligence(url):
    try:
        return get_domain_intelligence(url)
    except Exception as e:
        print(f"  Domain intelligence error: {e}")
        return {
            "domain_age_days": None, "has_https": None, "dns_resolves": None,
            "is_platform_hosted": False, "suspicious_tld": None,
            "reputation_signals": [], "certificate_valid": True,
            "certificate_error": None, "error": str(e)
        }


def safe_ip_intelligence(domain):
    try:
        return get_ip_intelligence(domain)
    except Exception as e:
        print(f"  IP intelligence error: {e}")
        return {"error": str(e)}


# ============================================
# Prediction Route
# ============================================
@app.route("/predict", methods=["POST"])
def predict():
    start_time = time.time()

    try:
        data = request.get_json()
        url = data["url"]

        print(f"\n{'='*60}")
        print(f"🔍 Processing: {url[:80]}...")
        print(f"{'='*60}")

        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path
        domain = domain.replace("www.", "")
        print(f"  Domain: {domain[:50]}")

        ti_confirmed, ti_source, ti_detail = check_threat_intelligence(url)
        if ti_confirmed:
            print(f"  🚨 {ti_source}: CONFIRMED PHISHING")

        domain_info = safe_domain_intelligence(url)
        domain_info["domain"] = domain
        domain_score, domain_signals = calculate_domain_reputation(domain_info, url)
        print(f"  🌐 Domain reputation: {domain_score}%")
        for signal in domain_signals[:3]:
            print(f"      - {signal}")

        features, reasons, url_reachable, page_content = [0]*30, [], True, ""
        try:
            result = extract_features(url, timeout=10)
            if len(result) == 4:
                features, reasons, url_reachable, page_content = result
            else:
                features, reasons, url_reachable = result
            print(f"  ✓ {len(features)} features extracted")
        except Exception as e:
            print(f"  ✗ Feature extraction: {e}")
            reasons = [f"Error: {str(e)[:50]}"]
            url_reachable = False

        url_score, url_signals = analyze_url_structure(reasons)
        if url_score > 0:
            print(f"  🔗 URL risk: {url_score}%")
            for signal in url_signals[:2]:
                print(f"      - {signal}")

        content_score, content_signals = 0, []
        if page_content:
            content_score, content_signals = analyze_page_content(page_content, url, domain)
            if content_score > 0:
                print(f"  📄 Content risk: {content_score}%")
                for signal in content_signals[:3]:
                    print(f"      - {signal}")

        prediction_prob = 0.5
        try:
            if scaler is not None and features:
                arr = np.array(features).reshape(1, -1)
                if hasattr(scaler, 'feature_names_in_') and scaler.feature_names_in_ is not None:
                    arr = pd.DataFrame(arr, columns=scaler.feature_names_in_)
                features_scaled = scaler.transform(arr)
                prediction_prob = get_ml_prediction(features_scaled)
                print(f"  🤖 ML: {prediction_prob:.4f}")
        except Exception as e:
            print(f"  ✗ ML error: {e}")

        final_probability, risk_factors = calculate_risk_score(
            prediction_prob, domain_info, reasons,
            content_score, content_signals,
            url_score, url_signals,
            domain_score, domain_signals,
            ti_confirmed, url
        )
        print(f"  🎯 Final: {final_probability:.4f} ({final_probability*100:.0f}%)")

        # Lower threshold for High Risk to catch more phishing
        if final_probability >= 0.45:
            final_label = "High Risk Phishing"
        elif final_probability >= 0.25:
            final_label = "Suspicious"
        else:
            final_label = "Legitimate"

        if ti_confirmed:
            final_label = "High Risk Phishing"

        ip_info = safe_ip_intelligence(domain)

        elapsed = time.time() - start_time
        print(f"  ⏱️  {elapsed:.2f}s")

        return jsonify({
            "prediction": final_label,
            "probability": float(final_probability),
            "base_probability": float(prediction_prob),
            "risk_factors": risk_factors,
            "threat_intelligence": {
                "confirmed_phishing": ti_confirmed,
                "source": ti_source,
                "detail": ti_detail,
            },
            "layers": {
                "domain_reputation": domain_score,
                "content_analysis": content_score,
                "url_structure": url_score,
                "ml_score": round(prediction_prob * 100, 1)
            },
            "domain_intelligence": {
                "domain_age_days": domain_info.get("domain_age_days"),
                "has_https": domain_info.get("has_https"),
                "dns_resolves": domain_info.get("dns_resolves"),
                "domain": domain,
                "is_platform_hosted": domain_info.get("is_platform_hosted", False),
                "platform_name": domain_info.get("platform_name"),
                "suspicious_tld": domain_info.get("suspicious_tld"),
                "certificate_valid": domain_info.get("certificate_valid", True),
                "certificate_error": domain_info.get("certificate_error"),
            },
            "ip_info": ip_info,
            "reasons": reasons[:15] if reasons else [],
            "processing_time": elapsed,
        })

    except Exception as e:
        elapsed = time.time() - start_time
        print(f"❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e), "prediction": "error", "probability": 0.0}), 500


if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=5000)