# ======================================
# PHASE 2: FLASK BACKEND FOR PREDICTION
# ======================================

from flask import Flask, request, jsonify
import tensorflow as tf
import numpy as np
import joblib
import os
from flask_cors import CORS
from feature_extractor import extract_features
import pandas as pd

# NEW IMPORTS
import whois
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)
CORS(app)

print("🔄 Loading model and scaler...")

# -------------------------------
# Load Model
# -------------------------------
model_path = os.path.join("..", "models", "phishing_model.h5")
model = tf.keras.models.load_model(model_path)

# -------------------------------
# Load Scaler
# -------------------------------
scaler_path = os.path.join("..", "models", "scaler.pkl")
scaler = joblib.load(scaler_path)

print("✅ Model and Scaler Loaded Successfully")


# ======================================
# DOMAIN INTELLIGENCE FUNCTION
# ======================================

def get_domain_intelligence(url):
    results = {
        "domain_age_days": 0,
        "has_https": 0,
        "dns_resolves": 0,
        "risk_flags": []
    }

    try:
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path
        domain = domain.replace("www.", "")

        # -------------------------
        # 1️⃣ HTTPS Check
        # -------------------------
        if parsed.scheme == "https":
            results["has_https"] = 1
        else:
            results["risk_flags"].append("No HTTPS detected")

        # -------------------------
        # 2️⃣ WHOIS Domain Age
        # -------------------------
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age_days = (datetime.now() - creation_date).days
                results["domain_age_days"] = age_days

                if age_days < 180:
                    results["risk_flags"].append("Very new domain (< 6 months)")
        except Exception:
            results["risk_flags"].append("WHOIS Data Unavailable")

        # -------------------------
        # 3️⃣ DNS Resolution Check
        # -------------------------
        try:
            dns.resolver.resolve(domain, 'A')
            results["dns_resolves"] = 1
        except Exception:
            results["risk_flags"].append("Domain does not resolve via DNS")

    except Exception:
        results["risk_flags"].append("Domain intelligence extraction failed")

    return results


# -------------------------------
# Home Route
# -------------------------------
@app.route("/")
def home():
    return "FedShield Backend is Running 🚀"


# -------------------------------
# Prediction Route
# -------------------------------
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        url = data["url"]

        print("URL received:", url)

        # -------------------------
        # 1️⃣ Extract UCI Features
        # -------------------------
        features, reasons = extract_features(url)

        features_df = pd.DataFrame([features], columns=scaler.feature_names_in_)
        features_scaled = scaler.transform(features_df)

        prediction_prob = model.predict(features_scaled)[0][0]

        # -------------------------
        # 2️⃣ Intelligent Risk Aggregation Layer
        # -------------------------

        domain_info = get_domain_intelligence(url)

        risk_score = 0
        risk_details = []

        # Weight configuration
        WEIGHTS = {
            "new_domain": 0.25,
            "no_https": 0.20,
            "dns_fail": 0.30
        }

        # 1️⃣ Domain Age Risk
        if domain_info["domain_age_days"] > 0 and domain_info["domain_age_days"] < 180:
            risk_score += WEIGHTS["new_domain"]
            risk_details.append("New domain risk applied")

        # 2️⃣ HTTPS Risk
        if domain_info["has_https"] == 0:
            risk_score += WEIGHTS["no_https"]
            risk_details.append("No HTTPS risk applied")

        # 3️⃣ DNS Resolution Risk
        if domain_info["dns_resolves"] == 0:
            risk_score += WEIGHTS["dns_fail"]
            risk_details.append("DNS resolution failure risk applied")

        # 4️⃣ Multi-factor amplification
        if risk_score >= 0.4:
            risk_score *= 1.2  # amplify if multiple red flags

        risk_score = min(risk_score, 0.6)  # cap dynamic risk

        final_probability = min(prediction_prob + risk_score, 1.0)

        # Final label
        if final_probability > 0.75:
            final_label = "High Risk Phishing"
        elif final_probability > 0.5:
            final_label = "Suspicious"
        else:
            final_label = "Legitimate"

        # -------------------------
        # 3️⃣ Return Response
        # -------------------------
        return jsonify({
            "prediction": final_label,
            "probability": float(final_probability),
            "base_probability": float(prediction_prob),
            "dynamic_signals": domain_info,
            "reasons": reasons,
            "features": features
        })

    except Exception as e:
        return jsonify({"error": str(e)})


# -------------------------------
# Run Server
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)