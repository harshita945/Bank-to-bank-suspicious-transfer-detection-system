import sys
from datetime import datetime, timedelta
from pathlib import Path
import unittest

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection import evaluate_transaction, detect_circular_transfers, load_ml_model


class TestDetectionEngine(unittest.TestCase):
    """Test suite for detection heuristics and machine learning."""

    def setUp(self):
        self.now = datetime.now()

    def test_ml_model_loading(self):
        """Verify that the pre-trained Scikit-Learn model loads successfully."""
        model, features = load_ml_model()
        self.assertIsNotNone(model, "ML Model should load successfully from models/ directory.")
        self.assertIsNotNone(features, "Feature list should load successfully.")
        self.assertTrue(hasattr(model, "predict_proba"), "Loaded model must have predict_proba method.")

    def test_normal_transaction(self):
        """Negative test case: verify an ordinary small transaction gets LOW risk."""
        cand = {
            "amount": 4500.00,
            "transaction_time": self.now,
            "sender_account_id": 1,
            "receiver_account_id": 2,
            "sender_bank_id": 1,
            "receiver_bank_id": 2
        }
        sender_history = [
            {"amount": 5000.00, "transaction_time": self.now - timedelta(days=2)},
            {"amount": 4200.00, "transaction_time": self.now - timedelta(days=5)}
        ]
        res = evaluate_transaction(cand, sender_history, [])
        self.assertEqual(res["risk_category"], "LOW")
        self.assertLess(res["risk_score"], 30)
        self.assertEqual(len(res["rule_flags"]), 0)

    def test_high_value_rule(self):
        """Verify high amount trigger >= 200,000."""
        cand = {
            "amount": 350000.00,
            "transaction_time": self.now,
            "sender_account_id": 1,
            "receiver_account_id": 2
        }
        res = evaluate_transaction(cand, [], [])
        self.assertIn("HIGH_VALUE_THRESHOLD", res["rule_flags"])
        self.assertGreaterEqual(res["risk_score"], 30)

    def test_velocity_burst_rule(self):
        """Verify frequency detection: >= 3 transfers in 15 minutes."""
        recent_sender = [
            {"amount": 10000, "transaction_time": self.now - timedelta(minutes=2)},
            {"amount": 12000, "transaction_time": self.now - timedelta(minutes=5)},
            {"amount": 15000, "transaction_time": self.now - timedelta(minutes=10)}
        ]
        cand = {
            "amount": 11000.00,
            "transaction_time": self.now,
            "sender_account_id": 1,
            "receiver_account_id": 3
        }
        res = evaluate_transaction(cand, recent_sender, [])
        self.assertIn("HIGH_VELOCITY_BURST", res["rule_flags"])

    def test_structuring_rule(self):
        """Verify structuring pattern detection near INR 50,000 threshold."""
        recent_history = [
            {"amount": 48500.00, "transaction_time": self.now - timedelta(hours=2)}
        ]
        cand = {
            "amount": 49200.00,
            "transaction_time": self.now,
            "sender_account_id": 1,
            "receiver_account_id": 2
        }
        res = evaluate_transaction(cand, recent_history, [])
        self.assertIn("STRUCTURING_PATTERN", res["rule_flags"])

    def test_circular_transfer_detection(self):
        """Verify NetworkX directed graph detects closed cycles A -> B -> C -> D -> A."""
        recent = [
            {"sender_account_number": "ACC-A", "receiver_account_number": "ACC-B", "amount": 100000},
            {"sender_account_number": "ACC-B", "receiver_account_number": "ACC-C", "amount": 99000},
            {"sender_account_number": "ACC-C", "receiver_account_number": "ACC-D", "amount": 98000}
        ]
        cand = {
            "sender_account_number": "ACC-D",
            "receiver_account_number": "ACC-A",
            "amount": 97000,
            "transaction_time": self.now
        }

        has_cycle, cycle_path, desc = detect_circular_transfers(cand, recent)
        self.assertTrue(has_cycle, "Circular transfer cycle must be flagged.")
        self.assertIn("ACC-A", cycle_path)
        self.assertIn("ACC-D", cycle_path)

        res = evaluate_transaction(cand, [], recent)
        self.assertEqual(res["risk_category"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 75)
        self.assertIn("CIRCULAR_TRANSFER_CYCLE", res["rule_flags"])


if __name__ == "__main__":
    unittest.main()
