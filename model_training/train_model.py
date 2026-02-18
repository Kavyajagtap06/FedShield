# ===============================
# PHASE 1: FINAL MODEL TRAINING
# ===============================

import pandas as pd
import numpy as np
from scipy.io import arff
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score
from imblearn.over_sampling import SMOTE
import tensorflow as tf
from tensorflow import keras
import joblib
import os

print("✅ Starting Model Training...")

# -------------------------------
# STEP 1: Load Dataset
# -------------------------------

data = arff.loadarff("../data/Training Dataset.arff")
df = pd.DataFrame(data[0])

# Decode bytes
for column in df.columns:
    if df[column].dtype == object:
        if isinstance(df[column].iloc[0], bytes):
            df[column] = df[column].str.decode('utf-8')

# Convert target to numeric
df['Result'] = df['Result'].astype(int)
df['Result'] = df['Result'].replace({-1: 0, 1: 1})

print("Dataset Loaded:", df.shape)

# -------------------------------
# STEP 2: Split Features & Target
# -------------------------------

X = df.drop("Result", axis=1)
y = df["Result"]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

print("Train shape:", X_train.shape)
print("Test shape:", X_test.shape)

# -------------------------------
# STEP 3: Handle Class Imbalance (SMOTE)
# -------------------------------

smote = SMOTE(random_state=42)
X_train_smote, y_train_smote = smote.fit_resample(X_train, y_train)

print("After SMOTE:", X_train_smote.shape)

# -------------------------------
# STEP 4: Feature Scaling
# -------------------------------

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train_smote)
X_test_scaled = scaler.transform(X_test)

# Save scaler (VERY IMPORTANT)
os.makedirs("../models", exist_ok=True)
joblib.dump(scaler, "../models/scaler.pkl")

print("Scaler saved.")

# -------------------------------
# STEP 5: Build Neural Network
# -------------------------------

def create_model(input_dim):
    model = keras.Sequential([
        keras.layers.Dense(64, activation='relu', input_shape=(input_dim,)),
        keras.layers.Dropout(0.3),
        keras.layers.Dense(32, activation='relu'),
        keras.layers.Dropout(0.2),
        keras.layers.Dense(1, activation='sigmoid')
    ])

    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall()]
    )

    return model

model = create_model(X_train_scaled.shape[1])

print("Model created.")

# -------------------------------
# STEP 6: Train Model
# -------------------------------

history = model.fit(
    X_train_scaled,
    y_train_smote,
    epochs=15,
    batch_size=32,
    validation_split=0.1,
    verbose=1
)

# -------------------------------
# STEP 7: Evaluate Model
# -------------------------------

y_pred_prob = model.predict(X_test_scaled)
y_pred = (y_pred_prob > 0.5).astype(int)

accuracy = accuracy_score(y_test, y_pred)
auc = roc_auc_score(y_test, y_pred_prob)

print("\n=== FINAL MODEL PERFORMANCE ===")
print("Accuracy:", round(accuracy, 4))
print("AUC:", round(auc, 4))
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# -------------------------------
# STEP 8: Save Final Model
# -------------------------------

model.save("../models/phishing_model.h5")
print("✅ Model saved successfully!")

print("\n🎯 PHASE 1 COMPLETED SUCCESSFULLY")
