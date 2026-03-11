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
from ip_intelligence import get_ip_intelligence
from domain_intelligence import get_domain_intelligence

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
        # Extract Domain (for IP intelligence)
        # -------------------------
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path
        domain = domain.replace("www.", "")

        # -------------------------
        # 1️⃣ Extract UCI Features
        # -------------------------
        features, reasons = extract_features(url)

        features_df = pd.DataFrame([features], columns=scaler.feature_names_in_)
        features_scaled = scaler.transform(features_df)

        prediction_prob = model.predict(features_scaled)[0][0]

        # -------------------------
        # 2️⃣ Domain Intelligence
        # -------------------------
        domain_info = get_domain_intelligence(url)

        # -------------------------
        # 3️⃣ IP Intelligence
        # -------------------------
        ip_info = get_ip_intelligence(domain)

        # -------------------------
        # Intelligent Risk Aggregation Layer
        # -------------------------
        risk_score = 0
        risk_details = []

        WEIGHTS = {
            "new_domain": 0.25,
            "no_https": 0.20,
            "dns_fail": 0.30
        }

        # Safely get values
        domain_age = domain_info.get("domain_age_days")
        has_https = domain_info.get("has_https")
        dns_resolves = domain_info.get("dns_resolves")

        # 1️⃣ Domain Age Risk
        if domain_age is not None and domain_age > 0 and domain_age < 180:
            risk_score += WEIGHTS["new_domain"]
            risk_details.append("New domain risk applied")

        # 2️⃣ HTTPS Risk
        if has_https is not None and has_https == 0:
            risk_score += WEIGHTS["no_https"]
            risk_details.append("No HTTPS risk applied")

        # 3️⃣ DNS Resolution Risk
        if dns_resolves is not None and dns_resolves == 0:
            risk_score += WEIGHTS["dns_fail"]
            risk_details.append("DNS resolution failure risk applied")

        # 4️⃣ Multi-factor amplification
        if risk_score >= 0.4:
            risk_score *= 1.2

        risk_score = min(risk_score, 0.6)

        final_probability = min(prediction_prob + risk_score, 1.0)

        # -------------------------
        # Final label
        # -------------------------
        if final_probability > 0.75:
            final_label = "High Risk Phishing"
        elif final_probability > 0.5:
            final_label = "Suspicious"
        else:
            final_label = "Legitimate"

        # -------------------------
        # Return Response
        # -------------------------
        return jsonify({
            "prediction": final_label,
            "probability": float(final_probability),
            "base_probability": float(prediction_prob),
            "dynamic_signals": domain_info,
            "ip_info": ip_info,
            "domain_intelligence": domain_info,
            "reasons": reasons,
            "features": features
        })

    except Exception as e:
        print("ERROR:", str(e))
        return jsonify({"error": str(e)})


# -------------------------------
# Run Server
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)