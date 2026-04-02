"""
Content analysis for phishing detection
Detects fake prize offers, brand impersonation, and deceptive content
"""

import re

# Common phishing keywords and patterns
PHISHING_KEYWORDS = {
    "prize_won": [
        "you won", "congratulations", "winner", "prize", "reward",
        "iphone", "samsung", "gift card", "amazon gift", "free gift",
        "you have been selected", "claim your", "receive your"
    ],
    "urgency": [
        "limited time", "act now", "expires today", "verify now",
        "immediate action", "your account will be suspended",
        "please verify", "action required"
    ],
    "fake_verification": [
        "verify your browser", "checking your connection", "browser check",
        "please wait while we verify", "captcha verification",
        "verifying your connection"
    ],
    "brand_impersonation": [
        "vinted", "paypal", "amazon", "microsoft", "apple",
        "netflix", "spotify", "bank of america", "chase", "fedex",
        "dhl", "ups", "usps", "apple id", "google"
    ],
    "suspicious_actions": [
        "receive your funds", "claim your prize", "enter your details",
        "confirm your identity", "update your payment", "verify your account"
    ]
}

def analyze_content(content, url):
    """
    Analyze webpage content for phishing indicators
    Returns: (risk_boost, detected_signals)
    """
    if not content:
        return 0, []
    
    content_lower = content.lower()
    detected_signals = []
    risk_boost = 0
    
    # Check for phishing keywords
    for category, keywords in PHISHING_KEYWORDS.items():
        for keyword in keywords:
            if keyword in content_lower:
                detected_signals.append(f"📝 {keyword.title()} (phishing keyword)")
                risk_boost += 0.05  # +5% per keyword
                break  # Count once per category to avoid spam
    
    # Special detection: Fake "Browser Verification" pages
    if "verify your browser" in content_lower or "checking your connection" in content_lower:
        risk_boost += 0.10
        detected_signals.append("⚠️ Fake browser verification page detected")
    
    # Special detection: Country selection (common in phishing)
    country_keywords = ["united states", "united kingdom", "canada", "australia", "germany", "france"]
    country_count = sum(1 for country in country_keywords if country in content_lower)
    if country_count >= 5:
        risk_boost += 0.10
        detected_signals.append(f"🌍 Multiple country options ({country_count}) - common in phishing")
    
    # Cap the boost
    risk_boost = min(risk_boost, 0.35)
    
    return risk_boost, detected_signals

def check_suspicious_subdomain(domain):
    """
    Check for suspicious subdomain patterns
    Example: vinted.xsk123.com (real brand + random domain)
    """
    if not domain:
        return False, None
    
    parts = domain.lower().split('.')
    
    if len(parts) >= 3:
        # Check if first part looks like a brand name
        brand_part = parts[0]
        known_brands = ['vinted', 'paypal', 'amazon', 'apple', 'microsoft', 'netflix', 
                        'google', 'facebook', 'instagram', 'whatsapp', 'fedex', 'dhl', 'ups']
        
        if brand_part in known_brands:
            # Check if the rest of the domain looks suspicious
            rest_domain = '.'.join(parts[1:])
            # Contains numbers OR is unusually long OR is a suspicious TLD
            if re.search(r'[0-9]', rest_domain) or len(rest_domain) > 15:
                return True, f"Suspicious subdomain: {brand_part}.{rest_domain} (brand impersonation)"
    
    return False, None