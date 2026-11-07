import unittest

from tests import TEST_DATABASE_URI
from app import app
from extensions import db
from models import User


class ReportsAPITests(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        app.config["SQLALCHEMY_DATABASE_URI"] = TEST_DATABASE_URI

        self.app_context = app.app_context()
        self.app_context.push()

        db.drop_all()
        db.create_all()

        user = User(
            username="report_analyst",
            role="security_analyst"
        )
        user.set_password("ReportPass!123")
        db.session.add(user)
        db.session.commit()

        self.client = app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def login(self):
        response = self.client.post(
            "/api/login",
            json={
                "username": "report_analyst",
                "password": "ReportPass!123"
            }
        )
        self.assertEqual(response.status_code, 200)

        me = self.client.get("/api/me")
        self.assertEqual(me.status_code, 200)

        return {"X-CSRFToken": me.get_json()["csrf_token"]}

    def test_reports_require_authentication(self):
        response = self.client.post("/api/reports", json={})
        self.assertEqual(response.status_code, 401)

    def test_reports_reject_invalid_input(self):
        headers = self.login()

        invalid_payloads = [
            {"incident": "invalid"},
            {"evidence": {"invalid": "object"}},
            {"available_tools": "invalid"}
        ]

        for payload in invalid_payloads:
            response = self.client.post(
                "/api/reports",
                json=payload,
                headers=headers
            )
            self.assertEqual(response.status_code, 400)

    def test_authenticated_user_can_generate_report(self):
        headers = self.login()

        response = self.client.post(
            "/api/reports",
            json={},
            headers=headers
        )

        self.assertEqual(response.status_code, 200)

        report = response.get_json()
        self.assertIn("report_id", report)
        self.assertIn("incident_summary", report)
        self.assertIn("evidence_inventory", report)
        self.assertIn("next_best_evidence", report)


if __name__ == "__main__":
    unittest.main()
