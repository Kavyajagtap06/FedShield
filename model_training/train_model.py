# ===============================
# IMPROVED MODEL TRAINING WITH MODERN PATTERNS
# Strategy 1: Training on combined UCI + Modern Phishing Patterns
# ===============================

import pandas as pd
import numpy as np
from scipy.io import arff
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score, confusion_matrix
from imblearn.over_sampling import SMOTE
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, callbacks
import joblib
import os
import warnings
warnings.filterwarnings('ignore')

print("="*60)
print("🚀 STRATEGY 1: TRAINING MODERN MODEL")
print("="*60)

# -------------------------------
# STEP 1: Load UCI Dataset
# -------------------------------
print("\n📂 Loading UCI Dataset...")
data = arff.loadarff("../data/Training Dataset.arff")
df_uci = pd.DataFrame(data[0])

# Convert all columns to numeric
for column in df_uci.columns:
    if df_uci[column].dtype == object:
        if isinstance(df_uci[column].iloc[0], bytes):
            df_uci[column] = df_uci[column].str.decode('utf-8')
        df_uci[column] = pd.to_numeric(df_uci[column], errors='coerce').fillna(-1)

# Convert target
df_uci['Result'] = df_uci['Result'].astype(int)
df_uci['Result'] = df_uci['Result'].replace({-1: 0, 1: 1})

print(f"UCI Dataset: {len(df_uci)} samples")
print(f"  Legitimate: {(df_uci['Result'] == 0).sum()}")
print(f"  Phishing: {(df_uci['Result'] == 1).sum()}")

# -------------------------------
# STEP 2: Create Modern Phishing Patterns
# -------------------------------
print("\n📂 Creating Modern Phishing Patterns...")

# Define patterns for modern phishing
modern_phishing_patterns = {
    'having_IP_Address': [1, 1, 1, 1, -1],
    'URL_Length': [1, 1, 1, 1, -1],
    'Shortining_Service': [1, 1, 1, -1, 1],
    'having_At_Symbol': [1, 1, -1, 1, -1],
    'double_slash_redirecting': [1, 1, 1, 1, -1],
    'Prefix_Suffix': [1, 1, 1, -1, 1],
    'having_Sub_Domain': [1, 1, 1, 1, -1],
    'SSLfinal_State': [1, 1, 1, 1, -1],
    'Domain_registeration_length': [1, 1, 1, 1, -1],
}

# Get feature columns (exclude Result)
feature_cols = [col for col in df_uci.columns if col != 'Result']
n_modern = 1500  # Create 1500 synthetic modern phishing samples

modern_features = []
for i in range(n_modern):
    sample = []
    for col in feature_cols:
        if col in modern_phishing_patterns:
            # Weighted towards suspicious patterns
            weights = [0.5, 0.25, 0.15, 0.05, 0.05]
            sample.append(np.random.choice(modern_phishing_patterns[col], p=weights))
        else:
            # Random for other features
            sample.append(np.random.choice([-1, 1], p=[0.3, 0.7]))
    modern_features.append(sample)

df_modern = pd.DataFrame(modern_features, columns=feature_cols)
df_modern['Result'] = 1  # All are phishing

print(f"Modern Phishing Dataset: {len(df_modern)} samples")

# -------------------------------
# STEP 3: Create Enhanced Legitimate Samples
# -------------------------------
print("\n📂 Creating Enhanced Legitimate Samples...")

legitimate_patterns = {
    'having_IP_Address': [-1, -1, -1, -1, -1],
    'URL_Length': [-1, -1, -1, -1, -1],
    'Shortining_Service': [-1, -1, -1, -1, -1],
    'having_At_Symbol': [-1, -1, -1, -1, -1],
    'double_slash_redirecting': [-1, -1, -1, -1, -1],
    'Prefix_Suffix': [-1, -1, -1, -1, -1],
    'having_Sub_Domain': [-1, -1, -1, -1, -1],
    'SSLfinal_State': [-1, -1, -1, -1, -1],
    'Domain_registeration_length': [-1, -1, -1, -1, -1],
}

n_legitimate = 1500
legitimate_features = []

for i in range(n_legitimate):
    sample = []
    for col in feature_cols:
        if col in legitimate_patterns:
            sample.append(np.random.choice(legitimate_patterns[col]))
        else:
            sample.append(np.random.choice([-1, 1], p=[0.8, 0.2]))
    legitimate_features.append(sample)

df_legitimate = pd.DataFrame(legitimate_features, columns=feature_cols)
df_legitimate['Result'] = 0  # All are legitimate

print(f"Enhanced Legitimate Dataset: {len(df_legitimate)} samples")

# -------------------------------
# STEP 4: Combine All Datasets
# -------------------------------
print("\n📂 Combining All Datasets...")
df_combined = pd.concat([df_uci, df_modern, df_legitimate], ignore_index=True)

# Shuffle the data
df_combined = df_combined.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"Combined Dataset: {len(df_combined)} samples")
print(f"  Legitimate: {(df_combined['Result'] == 0).sum()}")
print(f"  Phishing: {(df_combined['Result'] == 1).sum()}")

# -------------------------------
# STEP 5: Split Features & Target
# -------------------------------
X = df_combined.drop('Result', axis=1)
y = df_combined['Result']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

print(f"\n📊 Train set: {X_train.shape[0]} samples")
print(f"📊 Test set: {X_test.shape[0]} samples")

# -------------------------------
# STEP 6: Handle Class Imbalance with SMOTE
# -------------------------------
print("\n⚖️ Handling class imbalance with SMOTE...")

smote = SMOTE(random_state=42)
X_train_smote, y_train_smote = smote.fit_resample(X_train, y_train)

print(f"✅ After SMOTE: {X_train_smote.shape[0]} samples")
print(f"   Class distribution: {pd.Series(y_train_smote).value_counts().to_dict()}")

# -------------------------------
# STEP 7: Feature Scaling
# -------------------------------
print("\n📊 Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train_smote)
X_test_scaled = scaler.transform(X_test)

# Save scaler with feature names
os.makedirs("../models", exist_ok=True)
scaler.feature_names_in_ = np.array(feature_cols)
joblib.dump(scaler, "../models/scaler_modern.pkl")
print("✅ Scaler saved to ../models/scaler_modern.pkl")

# -------------------------------
# STEP 8: Build Improved Neural Network
# -------------------------------
print("\n🏗️ Building improved neural network...")

def create_improved_model(input_dim):
    """
    Improved model with:
    - Multiple layers for better learning
    - Dropout for regularization
    """
    model = keras.Sequential([
        # Input layer
        layers.Input(shape=(input_dim,)),
        
        # First hidden layer
        layers.Dense(256, activation='relu'),
        layers.BatchNormalization(),
        layers.Dropout(0.4),
        
        # Second hidden layer
        layers.Dense(128, activation='relu'),
        layers.BatchNormalization(),
        layers.Dropout(0.3),
        
        # Third hidden layer
        layers.Dense(64, activation='relu'),
        layers.Dropout(0.2),
        
        # Fourth hidden layer
        layers.Dense(32, activation='relu'),
        
        # Output layer
        layers.Dense(1, activation='sigmoid')
    ])
    
    # Use simple Adam optimizer with fixed learning rate
    optimizer = keras.optimizers.Adam(learning_rate=0.001)
    
    model.compile(
        optimizer=optimizer,
        loss='binary_crossentropy',
        metrics=[
            'accuracy',
            keras.metrics.Precision(name='precision'),
            keras.metrics.Recall(name='recall'),
            keras.metrics.AUC(name='auc')
        ]
    )
    
    return model

model = create_improved_model(X_train_scaled.shape[1])
print(f"✅ Model created with {X_train_scaled.shape[1]} input features")
model.summary()

# -------------------------------
# STEP 9: Train Model with Callbacks
# -------------------------------
print("\n🏋️ Training model...")

# Callbacks for better training
callbacks_list = [
    # Early stopping to prevent overfitting
    callbacks.EarlyStopping(
        monitor='val_loss',
        patience=10,
        restore_best_weights=True,
        verbose=1
    ),
    # Reduce learning rate when plateau
    callbacks.ReduceLROnPlateau(
        monitor='val_loss',
        factor=0.5,
        patience=5,
        min_lr=0.00001,
        verbose=1
    ),
    # Save best model
    callbacks.ModelCheckpoint(
        '../models/best_modern_model.h5',
        monitor='val_accuracy',
        save_best_only=True,
        verbose=1
    )
]

# Train with more epochs (will stop early if needed)
history = model.fit(
    X_train_scaled,
    y_train_smote,
    epochs=50,
    batch_size=64,
    validation_split=0.15,
    callbacks=callbacks_list,
    verbose=1
)

# -------------------------------
# STEP 10: Evaluate Model
# -------------------------------

print("\n📊 Evaluating model...")

# Predictions
y_pred_prob = model.predict(X_test_scaled)
y_pred = (y_pred_prob > 0.5).astype(int)

# Metrics
accuracy = accuracy_score(y_test, y_pred)
auc = roc_auc_score(y_test, y_pred_prob)
cm = confusion_matrix(y_test, y_pred)

print("\n" + "="*60)
print("📈 FINAL MODEL PERFORMANCE")
print("="*60)
print(f"\n✅ Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"✅ AUC-ROC: {auc:.4f}")

print("\n📊 Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

print("\n📊 Confusion Matrix:")
print(f"               Predicted")
print(f"              Legit  Phish")
print(f"Actual Legit:  {cm[0,0]:4d}   {cm[0,1]:4d}")
print(f"       Phish:  {cm[1,0]:4d}   {cm[1,1]:4d}")

# Calculate additional metrics
tn, fp, fn, tp = cm.ravel()
precision = tp / (tp + fp) if (tp + fp) > 0 else 0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0
f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

print(f"\n📊 Detailed Metrics:")
print(f"   Precision: {precision:.4f}")
print(f"   Recall: {recall:.4f}")
print(f"   F1-Score: {f1:.4f}")
print(f"   False Positive Rate: {fp/(fp+tn):.4f}")
print(f"   False Negative Rate: {fn/(fn+tp):.4f}")

# -------------------------------
# STEP 11: Save Final Model
# -------------------------------

model.save("../models/phishing_model_modern.h5")
print("\n✅ Model saved to ../models/phishing_model_modern.h5")

# Also save as .keras format
model.save("../models/phishing_model_modern.keras")

# Save training history
import json
history_dict = {
    'accuracy': [float(x) for x in history.history['accuracy']],
    'val_accuracy': [float(x) for x in history.history['val_accuracy']],
    'loss': [float(x) for x in history.history['loss']],
    'val_loss': [float(x) for x in history.history['val_loss']]
}
with open('../models/training_history_modern.json', 'w') as f:
    json.dump(history_dict, f)

print("✅ Training history saved")

print("\n" + "="*60)
print("🎯 STRATEGY 1 COMPLETED: Modern model trained successfully!")
print("="*60)