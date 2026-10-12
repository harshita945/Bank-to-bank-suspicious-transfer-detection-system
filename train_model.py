"""
Machine Learning Training Pipeline for Suspicious Transaction Detection.
Generates synthetic transaction dataset, extracts behavioral features,
trains a balanced Random Forest Classifier, evaluates performance metrics,
and saves the trained model artifact to models/.
"""

import os
import random
from datetime import datetime, timedelta
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split

from feature_engineering import FEATURE_COLUMNS, extract_features_from_dataframe

# Set seeds for reproducibility
np.random.seed(42)
random.seed(42)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)


def generate_synthetic_transactions(num_samples=3000):
    """
    Generate synthetic banking transaction records for academic modeling.
    Simulates ~90% regular banking activity and ~10% suspicious financial patterns.
    """
    records = []
    start_time = datetime(2026, 1, 1, 8, 0, 0)

    # 10 Fictional accounts across 5 banks
    account_ids = list(range(1, 11))
    bank_map = {1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 1, 7: 2, 8: 3, 9: 4, 10: 5}

    for i in range(num_samples):
        # Determine if this synthetic sample should simulate suspicious behavior (~10%)
        is_suspicious = 1 if (random.random() < 0.10) else 0

        sender = random.choice(account_ids)
        receiver = random.choice([acc for acc in account_ids if acc != sender])
        sender_bank = bank_map[sender]
        receiver_bank = bank_map[receiver]

        # Offset timestamp randomly over 60 days
        day_offset = random.randint(0, 60)

        if is_suspicious == 0:
            # NORMAL TRANSACTION PATTERNS
            # Regular business/day hours (08:00 to 20:00)
            hour = random.randint(8, 20)
            minute = random.randint(0, 59)
            tx_time = start_time + timedelta(days=day_offset, hours=hour, minutes=minute)

            # Normal amounts: typical retail or commercial transfers (500 to 75,000)
            amount = float(random.choice([
                random.uniform(500, 5000),
                random.uniform(5000, 25000),
                random.uniform(25000, 75000)
            ]))
            sender_tx_count_1h = random.choice([0, 0, 0, 1, 1])
            sender_tx_sum_1h = amount if sender_tx_count_1h > 0 else 0.0
            sender_avg_hist = random.uniform(15000, 45000)
            amount_ratio = amount / sender_avg_hist
            receiver_inflow_count_1h = random.choice([0, 1])
            rapid_forward_signal = 0

        else:
            # SUSPICIOUS PATTERNS (Money Laundering / Fraud typologies)
            typology = random.choice(["structuring", "velocity_burst", "high_amount_spike", "night_anomaly", "pass_through"])

            if typology == "structuring":
                # Multiple amounts intentionally just below standard 50,000 threshold
                hour = random.randint(9, 18)
                tx_time = start_time + timedelta(days=day_offset, hours=hour, minutes=random.randint(0, 59))
                amount = float(random.uniform(47000, 49800))
                sender_tx_count_1h = random.randint(2, 5)
                sender_tx_sum_1h = amount * sender_tx_count_1h
                sender_avg_hist = random.uniform(15000, 30000)
                amount_ratio = amount / sender_avg_hist
                receiver_inflow_count_1h = random.randint(1, 3)
                rapid_forward_signal = 0

            elif typology == "velocity_burst":
                # Rapid succession of transactions within minutes
                hour = random.randint(10, 17)
                tx_time = start_time + timedelta(days=day_offset, hours=hour, minutes=random.randint(0, 59))
                amount = float(random.uniform(30000, 80000))
                sender_tx_count_1h = random.randint(4, 9)
                sender_tx_sum_1h = amount * sender_tx_count_1h
                sender_avg_hist = random.uniform(20000, 35000)
                amount_ratio = amount / sender_avg_hist
                receiver_inflow_count_1h = random.randint(2, 5)
                rapid_forward_signal = 0

            elif typology == "high_amount_spike":
                # Extreme transaction amount anomaly compared to history
                hour = random.randint(9, 16)
                tx_time = start_time + timedelta(days=day_offset, hours=hour, minutes=random.randint(0, 59))
                amount = float(random.uniform(250000, 850000))
                sender_tx_count_1h = 1
                sender_tx_sum_1h = amount
                sender_avg_hist = random.uniform(15000, 35000)
                amount_ratio = amount / sender_avg_hist  # 8x to 25x historical average
                receiver_inflow_count_1h = 0
                rapid_forward_signal = 0

            elif typology == "night_anomaly":
                # Unusually large off-hours transfer
                hour = random.choice([0, 1, 2, 3, 4])
                tx_time = start_time + timedelta(days=day_offset, hours=hour, minutes=random.randint(0, 59))
                amount = float(random.uniform(120000, 350000))
                sender_tx_count_1h = random.randint(1, 3)
                sender_tx_sum_1h = amount
                sender_avg_hist = random.uniform(20000, 40000)
                amount_ratio = amount / sender_avg_hist
                receiver_inflow_count_1h = 1
                rapid_forward_signal = 0

            else:  # pass_through
                # Account rapidly receiving and transferring out full amount
                hour = random.randint(11, 16)
                tx_time = start_time + timedelta(days=day_offset, hours=hour, minutes=random.randint(0, 59))
                amount = float(random.uniform(80000, 180000))
                sender_tx_count_1h = random.randint(2, 4)
                sender_tx_sum_1h = amount * sender_tx_count_1h
                sender_avg_hist = random.uniform(30000, 60000)
                amount_ratio = amount / sender_avg_hist
                receiver_inflow_count_1h = random.randint(3, 6)
                rapid_forward_signal = 1

        records.append({
            "transaction_ref": f"TXN-SYNTH-{i+1:05d}",
            "sender_account_id": sender,
            "receiver_account_id": receiver,
            "sender_bank_id": sender_bank,
            "receiver_bank_id": receiver_bank,
            "amount": round(amount, 2),
            "transaction_time": tx_time.strftime("%Y-%m-%d %H:%M:%S"),
            "sender_tx_count_1h": sender_tx_count_1h,
            "sender_tx_sum_1h": round(sender_tx_sum_1h, 2),
            "sender_avg_amount_hist": round(sender_avg_hist, 2),
            "amount_to_avg_ratio": round(amount_ratio, 2),
            "receiver_inflow_count_1h": receiver_inflow_count_1h,
            "rapid_forward_signal": rapid_forward_signal,
            "is_suspicious": is_suspicious
        })

    df = pd.DataFrame(records)
    return df


def train_and_evaluate():
    """
    Main training workflow. Generates data, trains model, prints metrics,
    and serializes the classifier.
    """
    print("=" * 60)
    print("Bank-to-Bank Suspicious Transaction ML Pipeline")
    print("=" * 60)

    # 1. Generate or load synthetic dataset
    csv_path = DATA_DIR / "sample_transactions.csv"
    print(f"Generating synthetic transaction dataset ({3000} records)...")
    df = generate_synthetic_transactions(num_samples=3000)
    df.to_csv(csv_path, index=False)
    print(f"Saved dataset to: {csv_path}")

    # 2. Extract features
    print("Extracting behavioral and statistical features...")
    X = extract_features_from_dataframe(df)
    y = df["is_suspicious"].values

    suspicious_count = int(np.sum(y))
    normal_count = len(y) - suspicious_count
    print(f"Dataset Distribution: Normal = {normal_count} ({normal_count/len(y)*100:.1f}%), "
          f"Suspicious = {suspicious_count} ({suspicious_count/len(y)*100:.1f}%)")

    # 3. Train-Test Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )
    print(f"Train samples: {len(X_train)}, Test samples: {len(X_test)}")

    # 4. Train Scikit-Learn Random Forest Classifier
    print("Training Random Forest Classifier (balanced weights)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42
    )
    clf.fit(X_train, y_train)

    # 5. Evaluate on Test Split
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=["Normal", "Suspicious"])

    print("\n" + "=" * 30 + " Evaluation Metrics " + "=" * 30)
    print(f"Overall Accuracy: {accuracy * 100:.2f}%")
    print("\nConfusion Matrix:")
    print(f"  TN: {cm[0][0]:<4} | FP: {cm[0][1]}")
    print(f"  FN: {cm[1][0]:<4} | TP: {cm[1][1]}")
    print("\nClassification Report:")
    print(report)

    # 6. Feature Importances
    importances = sorted(
        zip(FEATURE_COLUMNS, clf.feature_importances_),
        key=lambda x: x[1],
        reverse=True
    )
    print("Top Feature Importances:")
    for feature_name, imp in importances[:6]:
        print(f"  - {feature_name:<28}: {imp * 100:.2f}%")

    # 7. Save Model & Feature Schema
    model_file = MODELS_DIR / "suspicious_transaction_model.joblib"
    features_file = MODELS_DIR / "model_features.joblib"

    joblib.dump(clf, model_file)
    joblib.dump(FEATURE_COLUMNS, features_file)
    print("\n" + "=" * 60)
    print(f"Saved trained model to: {model_file}")
    print(f"Saved feature list to:  {features_file}")
    print("=" * 60)

    return clf, accuracy


if __name__ == "__main__":
    train_and_evaluate()
