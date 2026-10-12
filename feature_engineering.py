"""
Feature Engineering Module for Suspicious Transaction Detection.
Prepares analytical features from transaction amounts, timing, frequency,
and historical account behaviors using Pandas and NumPy.
"""

import numpy as np
import pandas as pd


# List of numerical feature names used for ML model training and inference
FEATURE_COLUMNS = [
    "amount",
    "log_amount",
    "hour_of_day",
    "is_night_time",
    "is_weekend",
    "sender_tx_count_1h",
    "sender_tx_sum_1h",
    "sender_avg_amount_hist",
    "amount_to_avg_ratio",
    "is_near_threshold_structuring",
    "is_round_amount",
    "inter_bank_transfer",
    "receiver_inflow_count_1h",
    "rapid_forward_signal"
]


def extract_features_from_dataframe(df):
    """
    Given a DataFrame with transaction history and context,
    construct and return the tabular feature matrix X.
    
    Expected columns in df:
    - amount: float
    - transaction_time: datetime-like
    - sender_account_id: int/str
    - receiver_account_id: int/str
    - sender_bank_id: int/str
    - receiver_bank_id: int/str
    """
    df = df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df["transaction_time"]):
        df["transaction_time"] = pd.to_datetime(df["transaction_time"])

    # 1. Basic amount transformations
    df["log_amount"] = np.log1p(df["amount"].astype(float))

    # 2. Timing features
    df["hour_of_day"] = df["transaction_time"].dt.hour
    df["is_night_time"] = df["hour_of_day"].apply(lambda h: 1 if (h >= 23 or h < 5) else 0)
    df["day_of_week"] = df["transaction_time"].dt.dayofweek
    df["is_weekend"] = df["day_of_week"].apply(lambda d: 1 if d >= 5 else 0)

    # 3. Structuring and Round Amount features
    # Structuring: transfers clustered just below 50,000 threshold (45,000 - 49,999)
    df["is_near_threshold_structuring"] = df["amount"].apply(
        lambda a: 1 if (45000.0 <= float(a) <= 49999.0) else 0
    )
    df["is_round_amount"] = df["amount"].apply(
        lambda a: 1 if (float(a) % 5000.0 == 0 or float(a) % 10000.0 == 0) else 0
    )

    # 4. Inter-bank indicator
    if "sender_bank_id" in df.columns and "receiver_bank_id" in df.columns:
        df["inter_bank_transfer"] = (df["sender_bank_id"] != df["receiver_bank_id"]).astype(int)
    else:
        df["inter_bank_transfer"] = 1

    # Fill default values for historical aggregation columns if missing
    for col in [
        "sender_tx_count_1h",
        "sender_tx_sum_1h",
        "sender_avg_amount_hist",
        "amount_to_avg_ratio",
        "receiver_inflow_count_1h",
        "rapid_forward_signal"
    ]:
        if col not in df.columns:
            df[col] = 0.0

    # Ensure all numerical values are finite
    X = df[FEATURE_COLUMNS].fillna(0.0)
    return X


def build_single_transaction_features(
    amount,
    tx_time,
    sender_bank_id,
    receiver_bank_id,
    sender_recent_txs=None,
    sender_history=None,
    receiver_recent_txs=None
):
    """
    Construct a single-row feature dictionary for real-time model inference.
    
    Args:
        amount (float): Transaction amount.
        tx_time (datetime): Timestamp of transaction.
        sender_bank_id (int): Sender bank ID.
        receiver_bank_id (int): Receiver bank ID.
        sender_recent_txs (list): Transactions from sender in last 1 hour.
        sender_history (list): Historical transactions from sender.
        receiver_recent_txs (list): Transactions received by receiver in last 1 hour.
    """
    amount = float(amount)
    sender_recent_txs = sender_recent_txs or []
    sender_history = sender_history or []
    receiver_recent_txs = receiver_recent_txs or []

    hour = tx_time.hour
    is_night = 1 if (hour >= 23 or hour < 5) else 0
    is_weekend = 1 if tx_time.weekday() >= 5 else 0

    # Sender 1-hour window statistics
    sender_tx_count_1h = len(sender_recent_txs)
    sender_tx_sum_1h = sum(float(t.get("amount", 0)) for t in sender_recent_txs)

    # Historical average
    if sender_history:
        past_amounts = [float(t.get("amount", 0)) for t in sender_history]
        sender_avg_amount_hist = float(np.mean(past_amounts))
        ratio = (amount / sender_avg_amount_hist) if sender_avg_amount_hist > 0 else 1.0
    else:
        sender_avg_amount_hist = amount
        ratio = 1.0

    # Structuring flag
    is_structuring = 1 if (45000.0 <= amount <= 49999.0) else 0

    # Round number flag
    is_round = 1 if (amount % 5000.0 == 0 or amount % 10000.0 == 0) else 0

    # Inter-bank indicator
    inter_bank = 1 if (sender_bank_id != receiver_bank_id) else 0

    # Receiver recent inflow count
    receiver_inflow_count_1h = len(receiver_recent_txs)

    # Rapid forward signal (if receiver received funds and is rapidly sending them out)
    rapid_forward_signal = 1 if (receiver_inflow_count_1h >= 2 and sender_tx_count_1h >= 1) else 0

    feature_dict = {
        "amount": amount,
        "log_amount": float(np.log1p(amount)),
        "hour_of_day": hour,
        "is_night_time": is_night,
        "is_weekend": is_weekend,
        "sender_tx_count_1h": float(sender_tx_count_1h),
        "sender_tx_sum_1h": float(sender_tx_sum_1h),
        "sender_avg_amount_hist": float(sender_avg_amount_hist),
        "amount_to_avg_ratio": float(ratio),
        "is_near_threshold_structuring": is_structuring,
        "is_round_amount": is_round,
        "inter_bank_transfer": inter_bank,
        "receiver_inflow_count_1h": float(receiver_inflow_count_1h),
        "rapid_forward_signal": float(rapid_forward_signal)
    }

    # Return as 1-row DataFrame aligned with FEATURE_COLUMNS
    return pd.DataFrame([feature_dict])[FEATURE_COLUMNS]
