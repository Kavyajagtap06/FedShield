"""
FedShield Research Paper - Evaluation Script (RANDOM TEST SET)
===============================================================
- Fetches FRESH phishing URLs from PhishTank
- Uses random legitimate URLs from Tranco top sites
- Tests on URLs the model has never seen before
"""

import requests as req_lib
import numpy as np
import joblib
import os
import re
import csv
import time
import random
from datetime import datetime
from urllib.parse import urlparse

# ============================================
# Configuration
# ============================================
BACKEND_URL = "http://127.0.0.1:5000/predict"
MODELS_DIR = os.path.join("..", "models")
MODEL_PATH = os.path.join(MODELS_DIR, "phishing_model_modern.h5")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler_modern.pkl")

DELAY = 1.0
TIMEOUT = 30

# Number of URLs to test
N_PHISHING = 50   # Test on 50 random phishing URLs
N_LEGITIMATE = 50 # Test on 50 random legitimate URLs


# ============================================
# Fetch Fresh Phishing URLs from PhishTank
# ============================================
def fetch_fresh_phishing_urls(limit=50):
    """
    Fetch fresh phishing URLs from PhishTank's online feed
    Returns list of URLs
    """
    urls = []
    
    print("  🌐 Fetching fresh phishing URLs from PhishTank...")
    
    try:
        # PhishTank's online-valid feed (no API key needed)
        response = req_lib.get(
            "https://data.phishtank.com/data/online-valid.csv",
            timeout=15,
            headers={"User-Agent": "FedShield-Research/1.0"}
        )
        
        if response.status_code == 200:
            lines = response.text.strip().split('\n')
            print(f"  ✅ Got {len(lines)-1} total phishing URLs")
            
            # Extract URLs (skip header)
            for line in lines[1:limit+1]:
                parts = line.split(',')
                if len(parts) > 1:
                    url = parts[1].strip('"')
                    if url.startswith('http'):
                        urls.append(url)
            
            # Randomize order
            random.shuffle(urls)
            print(f"  ✅ Selected {len(urls)} random phishing URLs for testing")
            
        else:
            print(f"  ⚠️ PhishTank returned HTTP {response.status_code}")
            
    except Exception as e:
        print(f"  ⚠️ Could not fetch PhishTank feed: {e}")
        print("  Using fallback phishing URLs...")
        
        # Fallback phishing URLs
        urls = [
            "https://vinted.xsk123.com/receive/0229406",
            "https://paypal-secure-login.top/account/verify",
            "https://amazon-order-verify.sbs/confirm/payment",
            "https://dhl-parcel-track.cfd/confirm/delivery",
        ]
    
    return urls[:limit]


# ============================================
# Fetch Legitimate URLs from Tranco Top Sites
# ============================================
def fetch_legitimate_urls(limit=50):
    """
    Fetch legitimate URLs from Tranco top sites list
    """
    urls = []
    
    print("  🌐 Fetching legitimate URLs from Tranco...")
    
    try:
        # Tranco top 1M list (CSV format)
        response = req_lib.get(
            "https://tranco-list.eu/top-1m.csv.zip",
            timeout=20,
            headers={"User-Agent": "FedShield-Research/1.0"},
            stream=True
        )
        
        if response.status_code == 200:
            import zipfile
            import io
            
            z = zipfile.ZipFile(io.BytesIO(response.content))
            with z.open(z.namelist()[0]) as f:
                for i, line in enumerate(f):
                    if i >= limit:
                        break
                    parts = line.decode('utf-8').strip().split(',')
                    if len(parts) >= 2:
                        domain = parts[1].strip()
                        if domain and '.' in domain:
                            urls.append(f"https://{domain}")
            
            random.shuffle(urls)
            print(f"  ✅ Selected {len(urls)} random legitimate URLs for testing")
        else:
            print(f"  ⚠️ Tranco returned HTTP {response.status_code}")
            raise Exception("Tranco fetch failed")
            
    except Exception as e:
        print(f"  ⚠️ Could not fetch Tranco list: {e}")
        print("  Using fallback legitimate URLs...")
        
        # Fallback legitimate URLs
        urls = [
            "https://google.com",
            "https://github.com",
            "https://microsoft.com",
            "https://apple.com",
            "https://amazon.com",
            "https://facebook.com",
            "https://youtube.com",
            "https://twitter.com",
            "https://linkedin.com",
            "https://wikipedia.org",
        ]
    
    return urls[:limit]


# ============================================
# 10-FEATURE EXTRACTOR (Matches training)
# ============================================
def extract_10_features(url):
    """Extract the SAME 10 features used to train the model"""
    try:
        if not url.startswith("http"):
            url = "http://" + url
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "")
        path = parsed.path.lower()
        if ":" in domain:
            domain = domain.split(":")[0]

        f = []
        f.append(0 if parsed.scheme == "https" else 1)
        f.append(1 if len(url) > 75 else 0)
        f.append(1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', url) else 0)
        f.append(1 if "@" in url else 0)
        f.append(1 if url.count("//") > 1 else 0)
        f.append(1 if "-" in domain else 0)
        f.append(1 if domain.count(".") > 2 else 0)
        f.append(1 if re.search(r'bit\.ly|goo\.gl|tinyurl|ow\.ly', url) else 0)
        f.append(1 if parsed.query else 0)
        f.append(1 if len(path) > 30 else 0)

    except Exception:
        f = [0] * 10

    return np.array(f[:10], dtype=np.float32)


# ============================================
# Load Model
# ============================================
print("Loading retrained model and scaler...")
try:
    import tensorflow as tf
    ml_model = tf.keras.models.load_model(MODEL_PATH)
    ml_scaler = joblib.load(SCALER_PATH)
    print(f"  Model loaded from {MODEL_PATH}")
    print(f"  Scaler loaded from {SCALER_PATH}")
    ML_AVAILABLE = True
except Exception as e:
    print(f"  ERROR: Could not load model: {e}")
    ML_AVAILABLE = False


def get_ml_probability(url):
    """Get pure ML probability using 10 features"""
    if not ML_AVAILABLE:
        return 0.5
    
    try:
        features = extract_10_features(url)
        arr = features.reshape(1, -1)
        arr_scaled = ml_scaler.transform(arr)
        prob = float(ml_model.predict(arr_scaled, verbose=0)[0][0])
        return prob
    except Exception as e:
        print(f"    ML error: {e}")
        return 0.5


def label_from_prob(prob):
    """Match backend thresholds"""
    if prob >= 0.70:
        return "High Risk Phishing"
    elif prob >= 0.45:
        return "Suspicious"
    else:
        return "Legitimate"


def is_detected(label):
    return label in ["High Risk Phishing", "Suspicious"]


def call_backend(url):
    """Call FedShield backend"""
    try:
        r = req_lib.post(BACKEND_URL, json={"url": url}, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}", "probability": 0.5}
    except:
        return {"error": "timeout", "probability": 0.5}


# ============================================
# Main Evaluation
# ============================================

def run_evaluation():
    print("=" * 70)
    print("  FedShield Evaluation - Random Test Set")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    if not ML_AVAILABLE:
        print("\nERROR: Model not loaded. Run retrain_modern_model.py first.")
        return
    
    # Fetch test URLs
    print("\n[1/3] Fetching test URLs...")
    
    phishing_urls = fetch_fresh_phishing_urls(N_PHISHING)
    legitimate_urls = fetch_legitimate_urls(N_LEGITIMATE)
    
    if not phishing_urls:
        print("  ❌ No phishing URLs fetched. Exiting.")
        return
    
    if not legitimate_urls:
        print("  ❌ No legitimate URLs fetched. Exiting.")
        return
    
    results = []
    total = len(phishing_urls) + len(legitimate_urls)
    count = 0
    
    # Test phishing URLs
    print(f"\n[2/3] Testing {len(phishing_urls)} PHISHING URLs...\n")
    
    for url in phishing_urls:
        count += 1
        print(f"  [{count}/{total}] {url[:65]}...")
        
        ml_prob = get_ml_probability(url)
        backend = call_backend(url)
        hy_prob = backend.get("probability", 0.5)
        
        ml_label = label_from_prob(ml_prob)
        hy_label = label_from_prob(hy_prob)
        
        results.append({
            "url": url,
            "type": "Phishing",
            "ml_prob": round(ml_prob, 3),
            "hybrid_prob": round(hy_prob, 3),
            "ml_correct": is_detected(ml_label),
            "hybrid_correct": is_detected(hy_label),
        })
        
        ml_ok = "OK" if is_detected(ml_label) else "MISS"
        hy_ok = "OK" if is_detected(hy_label) else "MISS"
        print(f"       ML: {ml_prob:.3f} [{ml_ok}] | Hybrid: {hy_prob:.3f} [{hy_ok}]")
        time.sleep(DELAY)
    
    # Test legitimate URLs
    print(f"\n[3/3] Testing {len(legitimate_urls)} LEGITIMATE URLs...\n")
    
    for url in legitimate_urls:
        count += 1
        print(f"  [{count}/{total}] {url[:65]}...")
        
        ml_prob = get_ml_probability(url)
        backend = call_backend(url)
        hy_prob = backend.get("probability", 0.5)
        
        ml_label = label_from_prob(ml_prob)
        hy_label = label_from_prob(hy_prob)
        
        results.append({
            "url": url,
            "type": "Legitimate",
            "ml_prob": round(ml_prob, 3),
            "hybrid_prob": round(hy_prob, 3),
            "ml_correct": ml_label == "Legitimate",
            "hybrid_correct": hy_label == "Legitimate",
        })
        
        ml_ok = "OK" if ml_label == "Legitimate" else "FP"
        hy_ok = "OK" if hy_label == "Legitimate" else "FP"
        print(f"       ML: {ml_prob:.3f} [{ml_ok}] | Hybrid: {hy_prob:.3f} [{hy_ok}]")
        time.sleep(DELAY)
    
    # Calculate metrics
    ml_phish_correct = sum(1 for r in results if r["type"] == "Phishing" and r["ml_correct"])
    hy_phish_correct = sum(1 for r in results if r["type"] == "Phishing" and r["hybrid_correct"])
    total_phish = len(phishing_urls)
    
    ml_legit_correct = sum(1 for r in results if r["type"] == "Legitimate" and r["ml_correct"])
    hy_legit_correct = sum(1 for r in results if r["type"] == "Legitimate" and r["hybrid_correct"])
    total_legit = len(legitimate_urls)
    
    ml_detect = ml_phish_correct / total_phish * 100 if total_phish > 0 else 0
    hy_detect = hy_phish_correct / total_phish * 100 if total_phish > 0 else 0
    
    ml_fpr = (total_legit - ml_legit_correct) / total_legit * 100 if total_legit > 0 else 0
    hy_fpr = (total_legit - hy_legit_correct) / total_legit * 100 if total_legit > 0 else 0
    
    ml_acc = (ml_phish_correct + ml_legit_correct) / (total_phish + total_legit) * 100 if (total_phish + total_legit) > 0 else 0
    hy_acc = (hy_phish_correct + hy_legit_correct) / (total_phish + total_legit) * 100 if (total_phish + total_legit) > 0 else 0
    
    # Print results
    print("\n" + "=" * 70)
    print("  EVALUATION RESULTS (Random Test Set)")
    print("=" * 70)
    print(f"\nTest Set Size:")
    print(f"  Phishing URLs:   {total_phish}")
    print(f"  Legitimate URLs: {total_legit}")
    
    print(f"\nPHISHING DETECTION RATE (Higher is better)")
    print(f"  Pure ML:      {ml_detect:.1f}% ({ml_phish_correct}/{total_phish})")
    print(f"  FedShield:    {hy_detect:.1f}% ({hy_phish_correct}/{total_phish})")
    print(f"  IMPROVEMENT:  +{hy_detect - ml_detect:.1f}%")
    
    print(f"\nFALSE POSITIVE RATE (Lower is better)")
    print(f"  Pure ML:      {ml_fpr:.1f}% ({total_legit - ml_legit_correct}/{total_legit})")
    print(f"  FedShield:    {hy_fpr:.1f}% ({total_legit - hy_legit_correct}/{total_legit})")
    
    print(f"\nOVERALL ACCURACY")
    print(f"  Pure ML:      {ml_acc:.1f}%")
    print(f"  FedShield:    {hy_acc:.1f}%")
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = f"evaluation_results_{timestamp}.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "type", "ml_prob", "hybrid_prob", "ml_correct", "hybrid_correct"])
        writer.writeheader()
        writer.writerows(results)
    
    print(f"\nResults saved to {csv_path}")
    print("=" * 70)


if __name__ == "__main__":
    run_evaluation() 