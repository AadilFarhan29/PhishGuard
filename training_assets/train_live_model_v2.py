"""
PhishGuard — Retrain Live Model (v2)
Uses Kaggle Web Page Phishing Detection Dataset.
Run: python train_live_model_v2.py
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# ── CONFIG ──────────────────────────────────────────────────────────────────

DATASET_PATH = "data/phishing_dataset.csv"   # <── change to your CSV filename
MODEL_OUT     = "model/phishguard_live_model.pkl"
BACKUP_OUT    = "model/phishguard_live_model_old.pkl"
FEATURES_OUT  = "model/live_feature_columns.pkl"
LABEL_COL     = "status"

# URL-structural features only — all computable from URL string at runtime.
# No web_traffic / google_index / whois — those need live API calls.
FEATURE_COLS = [
    "length_url",
    "length_hostname",
    "ip",
    "nb_dots",
    "nb_hyphens",
    "nb_at",
    "nb_qm",
    "nb_and",
    "nb_eq",
    "nb_underscore",
    "nb_percent",
    "nb_slash",
    "nb_subdomains",
    "prefix_suffix",
    "shortening_service",
    "ratio_digits_url",
    "https_token",
    "tld_in_subdomain",
    "abnormal_subdomain",
    "phish_hints",
    "nb_redirection",
    "length_words_raw",
    "longest_words_raw",
    "nb_www",
    "nb_com",
]

# ── LOAD DATA ────────────────────────────────────────────────────────────────

print(f"\n[1/5] Loading dataset: {DATASET_PATH}")

if not os.path.exists(DATASET_PATH):
    raise FileNotFoundError(
        f"Dataset not found at '{DATASET_PATH}'.\n"
        f"Rename your CSV to 'phishing_dataset.csv' and put it in the data/ folder."
    )

df = pd.read_csv(DATASET_PATH)
print(f"      Loaded {len(df):,} rows × {len(df.columns)} columns")

# ── VALIDATE COLUMNS ─────────────────────────────────────────────────────────

print(f"\n[2/5] Validating columns...")

missing = [col for col in FEATURE_COLS + [LABEL_COL] if col not in df.columns]
if missing:
    raise ValueError(f"Missing columns in dataset: {missing}\nCheck your CSV headers.")

print(f"      All {len(FEATURE_COLS)} feature columns found ✓")
print(f"      Label column '{LABEL_COL}' found ✓")
print(f"      Label values: {df[LABEL_COL].unique()}")

# ── ENCODE LABELS ────────────────────────────────────────────────────────────

print(f"\n[3/5] Encoding labels...")

# Map: legitimate → 1 (safe), phishing → 0 (phishing)
# Handles both string and numeric labels
label_map = {}
unique_vals = df[LABEL_COL].unique()

for val in unique_vals:
    v = str(val).strip().lower()
    if v in ["legitimate", "benign", "safe", "1", "1.0"]:
        label_map[val] = 1
    elif v in ["phishing", "malicious", "phish", "0", "0.0"]:
        label_map[val] = 0
    else:
        raise ValueError(
            f"Unexpected label value: '{val}'. "
            f"Expected 'phishing'/'legitimate' or 0/1."
        )

df["label"] = df[LABEL_COL].map(label_map)

phishing_count   = (df["label"] == 0).sum()
legitimate_count = (df["label"] == 1).sum()
print(f"      Phishing:   {phishing_count:,}")
print(f"      Legitimate: {legitimate_count:,}")

# ── PREPARE FEATURES ─────────────────────────────────────────────────────────

print(f"\n[4/5] Preparing features and training...")

X = df[FEATURE_COLS].copy()
y = df["label"]

# Fill any nulls with 0 — shouldn't happen but safe
X = X.fillna(0)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"      Train set: {len(X_train):,} | Test set: {len(X_test):,}")

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    min_samples_split=4,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

print("      Training Random Forest (200 trees)...")
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n      ── RESULTS ──────────────────────────")
print(f"      Accuracy:  {accuracy * 100:.2f}%")
print(f"\n{classification_report(y_test, y_pred, target_names=['Phishing', 'Legitimate'])}")

# ── SAVE MODEL ───────────────────────────────────────────────────────────────

print(f"[5/5] Saving model...")

# Backup old model first
if os.path.exists(MODEL_OUT):
    os.rename(MODEL_OUT, BACKUP_OUT)
    print(f"      Old model backed up → {BACKUP_OUT}")

joblib.dump(model, MODEL_OUT)
joblib.dump(FEATURE_COLS, FEATURES_OUT)

print(f"      New model saved  → {MODEL_OUT}")
print(f"      Feature columns  → {FEATURES_OUT}")
print(f"\n✓ Done. Deploy the new model by pushing to GitHub.")
