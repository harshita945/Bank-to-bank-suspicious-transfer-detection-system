"""
Hybrid Suspicious Transaction Detection Engine.
Combines rule-based behavioral heuristics, NetworkX graph circular transfer detection,
and Scikit-learn machine learning probability into an explainable 0-100 risk score.
"""

from datetime import datetime, timedelta
import logging
from pathlib import Path
import joblib
import networkx as nx
import numpy as np

from config import Config
from feature_engineering import build_single_transaction_features

logger = logging.getLogger(__name__)

# Global model cache
_ML_MODEL = None
_MODEL_FEATURES = None


def load_ml_model():
    """
    Load saved scikit-learn model and feature column names.
    Gracefully handles missing or uninitialized models.
    """
    global _ML_MODEL, _MODEL_FEATURES
    if _ML_MODEL is not None:
        return _ML_MODEL, _MODEL_FEATURES

    model_path = Config.MODEL_PATH
    features_path = Config.FEATURE_NAMES_PATH

    if Path(model_path).exists() and Path(features_path).exists():
        try:
            _ML_MODEL = joblib.load(model_path)
            _MODEL_FEATURES = joblib.load(features_path)
            logger.info("Successfully loaded ML model from %s", model_path)
            return _ML_MODEL, _MODEL_FEATURES
        except Exception as e:
            logger.warning("Failed to load ML model: %s. Continuing with rule engine only.", e)
            return None, None
    else:
        logger.warning("ML model files not found at %s. Continuing with rule engine.", model_path)
        return None, None


def detect_circular_transfers(candidate_tx, recent_transactions, max_depth=Config.CIRCULAR_DEPTH_LIMIT):
    """
    Detect circular fund flows (e.g. A -> B -> C -> D -> A) using NetworkX directed graph analysis.
    
    Args:
        candidate_tx (dict): Current candidate transaction containing:
                             sender_account_id/number, receiver_account_id/number, amount, time.
        recent_transactions (list[dict]): Historical transactions in the recent analysis window.
        max_depth (int): Maximum cycle length to inspect.
        
    Returns:
        tuple: (has_cycle: bool, cycle_path: list[str], description: str)
    """
    # Build directed graph
    G = nx.DiGraph()

    # Normalize identifiers (use account_number or account_id as string)
    def acc_id(tx, key_num, key_id):
        return str(tx.get(key_num) or tx.get(key_id) or "UNKNOWN")

    for tx in recent_transactions:
        u = acc_id(tx, "sender_account_number", "sender_account_id")
        v = acc_id(tx, "receiver_account_number", "receiver_account_id")
        if u and v and u != v:
            G.add_edge(u, v, amount=float(tx.get("amount", 0)))

    # Add candidate edge
    cand_u = acc_id(candidate_tx, "sender_account_number", "sender_account_id")
    cand_v = acc_id(candidate_tx, "receiver_account_number", "receiver_account_id")
    G.add_edge(cand_u, cand_v, amount=float(candidate_tx.get("amount", 0)))

    try:
        # Search for elementary cycles
        cycles = list(nx.simple_cycles(G))
        for cycle in cycles:
            # Check if candidate sender and receiver participate in this cycle
            if len(cycle) >= 2 and len(cycle) <= max_depth:
                if cand_u in cycle and cand_v in cycle:
                    # Align cycle starting with cand_u
                    idx = cycle.index(cand_u)
                    ordered = cycle[idx:] + cycle[:idx] + [cand_u]
                    path_str = " -> ".join(ordered)
                    return True, ordered, f"Potential circular fund movement detected across connected accounts: {path_str}."
    except Exception as e:
        logger.warning("Graph cycle analysis exception: %s", e)

    return False, [], ""


def evaluate_transaction(
    candidate_tx,
    sender_history,
    recent_transactions,
    receiver_history=None
):
    """
    Complete hybrid evaluation of a single transaction.
    
    Args:
        candidate_tx (dict): The transaction being processed.
        sender_history (list[dict]): Historical transactions by the sender.
        recent_transactions (list[dict]): Transactions across all accounts in last 24-48 hours.
        receiver_history (list[dict]): Historical transactions involving receiver.
        
    Returns:
        dict: {
            "risk_score": int (0-100),
            "risk_category": "LOW" | "MEDIUM" | "HIGH",
            "rule_flags": list[str],
            "ml_probability": float (0.0 to 1.0),
            "reasons": list[str],
            "circular_path": list[str],
            "recommendation": str
        }
    """
    amount = float(candidate_tx["amount"])
    tx_time = candidate_tx["transaction_time"]
    if isinstance(tx_time, str):
        try:
            tx_time = datetime.fromisoformat(tx_time)
        except ValueError:
            tx_time = datetime.strptime(tx_time, "%Y-%m-%d %H:%M:%S")

    rule_flags = []
    reasons = []
    rule_score = 0

    # -------------------------------------------------------------
    # 1. RULE-BASED EVALUATION
    # -------------------------------------------------------------

    # Rule 1: High Transaction Amount
    past_amounts = [float(t["amount"]) for t in sender_history if float(t.get("amount", 0)) > 0]
    avg_past = float(np.mean(past_amounts)) if past_amounts else amount

    if amount >= Config.HIGH_AMOUNT_THRESHOLD:
        rule_flags.append("HIGH_VALUE_THRESHOLD")
        reasons.append(
            f"Transaction amount of INR {amount:,.2f} meets or exceeds the high-value monitoring threshold of INR {Config.HIGH_AMOUNT_THRESHOLD:,.2f}."
        )
        rule_score += 35
    elif past_amounts and len(past_amounts) >= 3 and amount >= (4.0 * avg_past) and amount > 50000:
        rule_flags.append("AMOUNT_ANOMALY_VS_HISTORY")
        reasons.append(
            f"Transaction amount of INR {amount:,.2f} is significantly higher than sender's historical average of INR {avg_past:,.2f} ({amount/avg_past:.1f}x average)."
        )
        rule_score += 25

    # Rule 2: Transaction Velocity (Frequency within short window)
    cutoff_velocity = tx_time - timedelta(minutes=Config.VELOCITY_WINDOW_MINUTES)
    recent_sender_txs = [
        t for t in sender_history
        if t.get("transaction_time") and (
            (t["transaction_time"] if isinstance(t["transaction_time"], datetime)
             else datetime.strptime(str(t["transaction_time"])[:19], "%Y-%m-%d %H:%M:%S")) >= cutoff_velocity
        )
    ]
    if len(recent_sender_txs) >= Config.VELOCITY_COUNT_THRESHOLD:
        rule_flags.append("HIGH_VELOCITY_BURST")
        reasons.append(
            f"High frequency of fund transfers detected: sender executed {len(recent_sender_txs)} transactions within {Config.VELOCITY_WINDOW_MINUTES} minutes."
        )
        rule_score += 30

    # Rule 3: Repeated Similar Amount Transfers
    cutoff_similar = tx_time - timedelta(hours=2)
    similar_count = 0
    tol = Config.SIMILAR_AMOUNT_TOLERANCE_PCT / 100.0
    for t in sender_history:
        t_time = t.get("transaction_time")
        if t_time:
            t_dt = t_time if isinstance(t_time, datetime) else datetime.strptime(str(t_time)[:19], "%Y-%m-%d %H:%M:%S")
            if t_dt >= cutoff_similar:
                t_amt = float(t.get("amount", 0))
                if abs(t_amt - amount) <= (amount * tol):
                    similar_count += 1
    if similar_count >= 2:
        rule_flags.append("REPEATED_SIMILAR_AMOUNTS")
        reasons.append(
            f"Multiple transfers of near-identical amounts (approx INR {amount:,.2f} +/- {Config.SIMILAR_AMOUNT_TOLERANCE_PCT}%) observed within 2 hours."
        )
        rule_score += 25

    # Rule 4: Potential Structuring / Smurfing
    is_in_structuring_range = (Config.STRUCTURING_LOWER_BOUND <= amount <= Config.STRUCTURING_UPPER_BOUND)
    if is_in_structuring_range:
        # Check if sender has made other transactions in this range recently (last 24h)
        cutoff_24h = tx_time - timedelta(hours=24)
        structuring_history_count = 0
        for t in sender_history:
            t_time = t.get("transaction_time")
            if t_time:
                t_dt = t_time if isinstance(t_time, datetime) else datetime.strptime(str(t_time)[:19], "%Y-%m-%d %H:%M:%S")
                if t_dt >= cutoff_24h:
                    t_amt = float(t.get("amount", 0))
                    if Config.STRUCTURING_LOWER_BOUND <= t_amt <= Config.STRUCTURING_UPPER_BOUND:
                        structuring_history_count += 1

        if structuring_history_count >= 1:
            rule_flags.append("STRUCTURING_PATTERN")
            reasons.append(
                f"Structuring pattern detected: repeated transfers intentionally clustered just below INR 50,000 regulatory reporting threshold (amount: INR {amount:,.2f})."
            )
            rule_score += 35

    # Rule 5: Rapid Pass-through / Rapid Fund Movement
    receiver_history = receiver_history or []
    cutoff_rapid = tx_time - timedelta(minutes=Config.RAPID_FORWARD_WINDOW_MINUTES)
    recent_inflows = [
        t for t in receiver_history
        if t.get("receiver_account_id") == candidate_tx.get("sender_account_id")
    ]
    # Check if candidate sender recently received substantial funds and is immediately forwarding
    sender_inflows_recently = [
        t for t in recent_transactions
        if str(t.get("receiver_account_id")) == str(candidate_tx.get("sender_account_id"))
        and (
            t.get("transaction_time") is None or (
                (t["transaction_time"] if isinstance(t["transaction_time"], datetime)
                 else datetime.strptime(str(t["transaction_time"])[:19], "%Y-%m-%d %H:%M:%S")) >= cutoff_rapid
            )
        )
    ]
    if sender_inflows_recently:
        total_inflow = sum(float(t.get("amount", 0)) for t in sender_inflows_recently)
        if total_inflow > 0 and (amount >= 0.70 * total_inflow):
            rule_flags.append("RAPID_FUND_MOVEMENT")
            reasons.append(
                f"Rapid pass-through movement: account received INR {total_inflow:,.2f} within the last {Config.RAPID_FORWARD_WINDOW_MINUTES} minutes and immediately transferred out INR {amount:,.2f} ({amount/total_inflow*100:.1f}%)."
            )
            rule_score += 30

    # Rule 6: Unusual Off-hours Timing
    hour = tx_time.hour
    if (hour >= 23 or hour < 5) and amount >= 75000:
        rule_flags.append("OFF_HOURS_HIGH_VALUE")
        reasons.append(
            f"Unusual transaction timing: high-value transfer submitted at {tx_time.strftime('%H:%M:%S')} outside standard banking hours."
        )
        rule_score += 20

    # Rule 7: Circular Fund Movement (NetworkX Directed Graph)
    has_cycle, cycle_path, cycle_desc = detect_circular_transfers(candidate_tx, recent_transactions)
    if has_cycle:
        rule_flags.append("CIRCULAR_TRANSFER_CYCLE")
        reasons.append(cycle_desc)
        rule_score += 55

    # Cap rule score to 100
    rule_score = min(100, rule_score)

    # -------------------------------------------------------------
    # 2. MACHINE LEARNING EVALUATION
    # -------------------------------------------------------------
    model, feature_cols = load_ml_model()
    ml_probability = 0.0

    if model is not None:
        try:
            X_single = build_single_transaction_features(
                amount=amount,
                tx_time=tx_time,
                sender_bank_id=candidate_tx.get("sender_bank_id", 1),
                receiver_bank_id=candidate_tx.get("receiver_bank_id", 2),
                sender_recent_txs=recent_sender_txs,
                sender_history=sender_history,
                receiver_recent_txs=sender_inflows_recently
            )
            # Predict class 1 (Suspicious) probability
            probs = model.predict_proba(X_single)
            ml_probability = float(probs[0][1])
        except Exception as e:
            logger.warning("ML model inference failed: %s. Using default probability.", e)
            ml_probability = 0.10
    else:
        # Fallback approximation based on rule score if model file is not present
        ml_probability = min(1.0, rule_score / 100.0)

    # -------------------------------------------------------------
    # 3. COMPOSITE RISK SCORE CALCULATION
    # -------------------------------------------------------------
    # Weighted combination: 55% Rule Score + 45% ML Probability Score
    combined_score = round((0.55 * rule_score) + (0.45 * (ml_probability * 100.0)))

    # If circular transfer was detected or multiple high-severity flags triggered, ensure High risk
    if has_cycle:
        combined_score = max(combined_score, 75)
    elif len(rule_flags) >= 2 and rule_score >= 50:
        combined_score = max(combined_score, 65)

    final_score = int(np.clip(combined_score, 0, 100))

    # Determine Risk Category
    if final_score >= 60:
        risk_category = "HIGH"
        recommendation = (
            "FLAGGED FOR IMMEDIATE INVESTIGATION: Escalate to Senior Financial Crime Compliance Officer. "
            "Freeze outgoing settlement pending Enhanced Due Diligence (EDD) and evaluate preparation of Suspicious Activity Report (SAR)."
        )
    elif final_score >= 30:
        risk_category = "MEDIUM"
        recommendation = (
            "ROUTINE MONITORING & REVIEW: Assign to Compliance Analyst for secondary verification. "
            "Request business documentation or transaction invoice from the sending party within 24 hours."
        )
    else:
        risk_category = "LOW"
        recommendation = (
            "TRANSACTION CLEARED: Regular banking activity. Transaction parameters fall within expected historical variance. No action required."
        )

    # Clean default reason if no rules triggered
    if not reasons:
        reasons.append("Transaction amount and frequency align with normal historical benchmarks.")

    return {
        "risk_score": final_score,
        "risk_category": risk_category,
        "rule_flags": rule_flags,
        "ml_probability": round(ml_probability, 4),
        "reasons": reasons,
        "circular_path": cycle_path,
        "recommendation": recommendation
    }
