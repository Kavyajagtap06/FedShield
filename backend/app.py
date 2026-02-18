# ======================================
# PHASE 2: FLASK BACKEND FOR PREDICTION
# ======================================

from flask import Flask, request, jsonify
import tensorflow as tf
import numpy as np
import joblib
import os
from flask_cors import CORS

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

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

        # Extract features
        features = data["features"]

        # Convert to numpy array
        features_array = np.array(features).reshape(1, -1)

        # Scale features
        features_scaled = scaler.transform(features_array)

        # Make prediction
        prediction_prob = model.predict(features_scaled)[0][0]

        prediction_label = "Phishing" if prediction_prob > 0.5 else "Legitimate"

        return jsonify({
            "prediction": prediction_label,
            "probability": float(prediction_prob)
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        })

# -------------------------------
# Run Server
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)
