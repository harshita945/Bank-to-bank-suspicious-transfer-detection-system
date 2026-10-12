"""
Flask Route and Controller Integration Tests.
Verifies application startup, authentication restrictions, input validations,
and error handling.
"""

import sys
from pathlib import Path
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import app


class TestFlaskRoutes(unittest.TestCase):
    """Integration test suite for Flask endpoints."""

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

    def test_app_startup_and_login_page(self):
        """Verify root redirects and login page loads with HTTP 200."""
        res_root = self.client.get("/")
        self.assertEqual(res_root.status_code, 302)

        res_login = self.client.get("/login")
        self.assertEqual(res_login.status_code, 200)
        self.assertIn(b"BankGuard AML", res_login.data)
        self.assertIn(b"Academic Demo Credentials", res_login.data)

    def test_protected_routes_redirect_when_unauthenticated(self):
        """Verify unauthorized access to dashboard/transfer redirects to login."""
        protected_endpoints = ["/dashboard", "/transfer", "/transactions", "/alerts", "/accounts", "/reports", "/admin"]
        for ep in protected_endpoints:
            res = self.client.get(ep)
            self.assertEqual(res.status_code, 302, f"Endpoint {ep} should redirect when not logged in.")
            self.assertIn("/login", res.headers.get("Location", ""))

    def test_api_health_endpoint(self):
        """Verify system health endpoint returns JSON."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("database_connected", data)
        self.assertIn("timestamp", data)

    def test_admin_access_restricted_for_regular_user(self):
        """Verify role-based access control blocks non-admin from /admin."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = 2
            sess["username"] = "analyst"
            sess["user_role"] = "analyst"

        res = self.client.get("/admin")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/dashboard", res.headers.get("Location", ""))

    @mock.patch("database.query_db")
    def test_transfer_validation_same_sender_receiver(self, mock_query):
        """Verify backend validation blocks transfer between an account and itself."""
        mock_query.return_value = [
            {"id": 1, "account_number": "ACC-1001", "account_holder_name": "Aarav", "balance": 50000, "bank_name": "SBI", "bank_code": "SBI"}
        ]
        with self.client.session_transaction() as sess:
            sess["user_id"] = 2
            sess["username"] = "analyst"
            sess["user_role"] = "analyst"
            sess["_csrf_token"] = "valid_test_token"

        res = self.client.post("/transfer", data={
            "csrf_token": "valid_test_token",
            "sender_account_id": "1",
            "receiver_account_id": "1",
            "amount": "5000.00"
        })
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"between an account and itself are prohibited", res.data)

    @mock.patch("database.query_db")
    def test_transfer_validation_invalid_amount(self, mock_query):
        """Verify backend validation blocks negative or non-numerical amounts."""
        mock_query.return_value = [
            {"id": 1, "account_number": "ACC-1001", "account_holder_name": "Aarav", "balance": 50000, "bank_name": "SBI", "bank_code": "SBI"}
        ]
        with self.client.session_transaction() as sess:
            sess["user_id"] = 2
            sess["username"] = "analyst"
            sess["user_role"] = "analyst"
            sess["_csrf_token"] = "valid_test_token"

        res = self.client.post("/transfer", data={
            "csrf_token": "valid_test_token",
            "sender_account_id": "1",
            "receiver_account_id": "2",
            "amount": "-500.00"
        })
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"valid positive numerical amount", res.data)


if __name__ == "__main__":
    unittest.main()
