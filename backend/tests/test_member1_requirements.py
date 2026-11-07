"""Reconstructed source for the original Member 1 requirement tests.

This file was rebuilt from the Python 3.11 bytecode in
recovery/original_member1_tests.pyc and the corresponding disassembly captured in
recovery/member1_recovered_disassembly.txt. It intentionally does not touch the
live project test file and marks any area that cannot be recovered with high
confidence.
"""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests import TEST_DATABASE_URI
from app import app, ensure_bootstrap_administrator, migrate_legacy_roles
from config import AppConfig
from extensions import db
from investigation.evidence_manager import identify_missing_evidence
from investigation.nbe_engine import select_next_best_tool
from models import User


class Member1RequirementsTests(unittest.TestCase):
    """Recovered from the original Python 3.11 .pyc backup.

    Uncertain sections are explicitly marked to avoid inventing logic that cannot be
    established from the bytecode. The critical behavior and public API contracts
    match the current Flask app and project tests.
    """

    def setUp(self):
        self.assertIn("sentinelx-tests", app.config["SQLALCHEMY_DATABASE_URI"])
        self.assertNotIn(r"backend\sentinelx.db", app.config["SQLALCHEMY_DATABASE_URI"])
        self.assertEqual(app.config["SQLALCHEMY_DATABASE_URI"], TEST_DATABASE_URI)

        self.app_context = app.app_context()
        self.app_context.push()
        db.drop_all()
        db.create_all()
        self.client = app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_registration_login_logout_flow(self):
        response = self.client.post(
            "/api/register",
            json={"username": "alice", "password": "s3cretPass!", "role": "user"},
        )
        self.assertEqual(response.status_code, 201)

        payload = response.get_json()
        self.assertEqual(payload["user"]["username"], "alice")
        self.assertEqual(payload["user"]["role"], "security_analyst")

        login_response = self.client.post(
            "/api/login",
            json={"username": "alice", "password": "s3cretPass!"},
        )
        self.assertEqual(login_response.status_code, 200)

        me_response = self.client.get("/api/me")
        self.assertEqual(me_response.status_code, 200)

        csrf_headers = {"X-CSRFToken": me_response.get_json()["csrf_token"]}
        self.assertTrue(csrf_headers["X-CSRFToken"])

        logout_response = self.client.post("/api/logout")
        self.assertEqual(logout_response.status_code, 200)
        self.assertEqual(logout_response.get_json()["message"], "Logged out successfully.")

    def test_registration_ignores_admin_role_and_session_security(self):
        response = self.client.post(
            "/api/register",
            json={"username": "alice", "password": "s3cretPass!", "role": "admin"},
        )
        self.assertEqual(response.status_code, 201)

        payload = response.get_json()
        self.assertEqual(payload["user"]["role"], "security_analyst")
        self.assertNotEqual(payload["user"]["role"], "administrator")

        cookie_header = response.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie_header)
        self.assertIn("SameSite=Lax", cookie_header)

    def test_public_registration_ignores_role_overrides(self):
        # Uncertain: exact username values for every sub-case are reconstructed from the
        # bytecode tuple of cases; the logic is confirmed to iterate registrations.
        for username, role in (
            ("public_none", None),
            ("public_admin", "administrator"),
            ("public_bad_admin", "admin"),
        ):
            response = self.client.post(
                "/api/register",
                json={"username": username, "password": "s3cretPass!", "role": role},
            )
            self.assertEqual(response.status_code, 201)
            payload = response.get_json()
            self.assertEqual(payload["user"]["username"], username)
            self.assertEqual(payload["user"]["role"], "security_analyst")
            self.client.post("/api/logout")

        registered = User.query.filter_by(username="public_admin").first()
        self.assertIsNotNone(registered)
        self.assertEqual(registered.role, "security_analyst")

    def test_password_hashing_and_rbac(self):
        admin_user = User(username="adminuser", role="administrator")
        admin_user.set_password("AdminPass!23")

        analyst = User(username="analyst", role="security_analyst")
        analyst.set_password("InvestPass!23")

        db.session.add_all([admin_user, analyst])
        db.session.commit()

        self.assertNotEqual(admin_user.password_hash, "AdminPass!23")
        self.assertTrue(admin_user.check_password("AdminPass!23"))
        self.assertFalse(admin_user.check_password("wrong-pass"))

        analyst_login = self.client.post(
            "/api/login",
            json={"username": "analyst", "password": "InvestPass!23"},
        )
        self.assertEqual(analyst_login.status_code, 200)

        forbidden = self.client.get("/api/admin/users")
        self.assertEqual(forbidden.status_code, 403)

        self.client.post("/api/logout")

        admin_login = self.client.post(
            "/api/login",
            json={"username": "adminuser", "password": "AdminPass!23"},
        )
        self.assertEqual(admin_login.status_code, 200)

        allowed = self.client.get("/api/admin/users")
        self.assertEqual(allowed.status_code, 200)
        self.assertGreaterEqual(allowed.get_json()["count"], 2)

    def test_legacy_role_migration(self):
        admin_user = User(
            username="legacy-admin",
            email="legacy-admin@example.com",
            role="admin",
        )
        admin_user.set_password("LegacyPass!12")

        analyst_user = User(
            username="legacy-investigator",
            email="legacy-investigator@example.com",
            role="investigator",
        )
        analyst_user.set_password("LegacyPass!34")

        db.session.add_all([admin_user, analyst_user])
        db.session.commit()

        migrate_legacy_roles()

        db.session.refresh(admin_user)
        db.session.refresh(analyst_user)

        self.assertEqual(admin_user.role, "administrator")
        self.assertEqual(analyst_user.role, "security_analyst")

        for user in User.query.all():
            self.assertNotIn(user.role, {"admin", "investigator"})

    def test_production_secret_requirements_and_bootstrap(self):
        with patch.object(AppConfig, "ENV", "production", create=True):
            with patch.dict(
                os.environ,
                {
                    "SENTINELX_ENV": "production",
                    "SENTINELX_SECRET_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                },
                clear=True,
            ):
                self.assertRaises(RuntimeError, AppConfig.validate)

        with patch.object(AppConfig, "ENV", "production", create=True):
            with patch.dict(
                os.environ,
                {
                    "SENTINELX_ENV": "production",
                    "SENTINELX_SECRET_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "SENTINELX_BOOTSTRAP_ADMIN_USERNAME": "bootstrap-admin",
                    "SENTINELX_BOOTSTRAP_ADMIN_PASSWORD": "StrongBootstrapPass!12",
                    "BOOTSTRAP_ADMIN_USERNAME": "",
                    "BOOTSTRAP_ADMIN_PASSWORD": "",
                },
                clear=True,
            ):
                bootstrap_admin = ensure_bootstrap_administrator()
                self.assertIsNotNone(bootstrap_admin)
                self.assertEqual(bootstrap_admin.username, "bootstrap-admin")
                self.assertEqual(bootstrap_admin.role, "administrator")

        existing_admin = User(
            username="persistent-admin",
            email="persistent-admin@example.com",
            role="administrator",
            status="active",
        )
        existing_admin.set_password("ExistingPassword!12")
        db.session.add(existing_admin)
        db.session.commit()

        with patch.object(AppConfig, "ENV", "production", create=True):
            with patch.dict(
                os.environ,
                {
                    "SENTINELX_ENV": "production",
                    "SENTINELX_SECRET_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "SENTINELX_BOOTSTRAP_ADMIN_USERNAME": "new-bootstrap-admin",
                    "SENTINELX_BOOTSTRAP_ADMIN_PASSWORD": "AnotherStrongPass!12",
                    "BOOTSTRAP_ADMIN_USERNAME": "",
                    "BOOTSTRAP_ADMIN_PASSWORD": "",
                },
                clear=True,
            ):
                user = ensure_bootstrap_administrator()
                self.assertIsNotNone(user)
                self.assertEqual(user.id, bootstrap_admin.id)
                self.assertTrue(bootstrap_admin.check_password("StrongBootstrapPass!12"))

    def test_bootstrap_requires_valid_production_configuration(self):
        with patch.object(AppConfig, "ENV", "production", create=True):
            with patch.dict(
                os.environ,
                {
                    "SENTINELX_ENV": "production",
                    "SENTINELX_SECRET_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "BOOTSTRAP_ADMIN_USERNAME": "",
                    "BOOTSTRAP_ADMIN_PASSWORD": "",
                },
                clear=True,
            ):
                with self.assertRaisesRegex(RuntimeError, "Production requires bootstrap administrator credentials"):
                    ensure_bootstrap_administrator()

        with patch.object(AppConfig, "ENV", "production", create=True):
            with patch.dict(
                os.environ,
                {
                    "SENTINELX_ENV": "production",
                    "SENTINELX_SECRET_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "SENTINELX_BOOTSTRAP_ADMIN_USERNAME": "bootstrap-admin",
                    "BOOTSTRAP_ADMIN_PASSWORD": "StrongBootstrapPass!12",
                    "BOOTSTRAP_ADMIN_USERNAME": "",
                },
                clear=True,
            ):
                with self.assertRaisesRegex(RuntimeError, "requires both username and password"):
                    ensure_bootstrap_administrator()

        with patch.object(AppConfig, "ENV", "production", create=True):
            with patch.dict(
                os.environ,
                {
                    "SENTINELX_ENV": "production",
                    "SENTINELX_SECRET_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "SENTINELX_BOOTSTRAP_ADMIN_PASSWORD": "StrongBootstrapPass!12",
                    "BOOTSTRAP_ADMIN_USERNAME": "",
                    "BOOTSTRAP_ADMIN_PASSWORD": "",
                },
                clear=True,
            ):
                with self.assertRaisesRegex(RuntimeError, "requires both username and password"):
                    ensure_bootstrap_administrator()

        db.session.query(User).filter_by(username="bootstrap-admin").delete()
        db.session.commit()

        existing_admin = User(
            username="existing-admin-legacy",
            email="existing-admin-legacy@example.com",
            role="administrator",
            status="active",
        )
        existing_admin.set_password("ExistingLegacy!12")
        db.session.add(existing_admin)
        db.session.commit()

        with patch.object(AppConfig, "ENV", "production", create=True):
            with patch.dict(
                os.environ,
                {
                    "SENTINELX_ENV": "production",
                    "SENTINELX_SECRET_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "BOOTSTRAP_ADMIN_USERNAME": "legacy-admin",
                    "BOOTSTRAP_ADMIN_PASSWORD": "LegacyBootstrapPass!12",
                    "SENTINELX_BOOTSTRAP_ADMIN_USERNAME": "",
                    "SENTINELX_BOOTSTRAP_ADMIN_PASSWORD": "",
                },
                clear=True,
            ):
                user = ensure_bootstrap_administrator()
                self.assertIsNotNone(user)
                self.assertEqual(user.id, existing_admin.id)
                self.assertEqual(user.username, "existing-admin-legacy")
                self.assertEqual(user.role, "administrator")

    def test_bootstrap_preserves_existing_admin_and_allows_dev_without_credentials(self):
        existing_admin = User(
            username="existing-admin",
            email="existing-admin@example.com",
            role="administrator",
            status="active",
        )
        existing_admin.set_password("ExistingPassword!12")
        db.session.add(existing_admin)
        db.session.commit()

        with patch.object(AppConfig, "ENV", "production", create=True):
            with patch.dict(
                os.environ,
                {
                    "SENTINELX_ENV": "production",
                    "SENTINELX_SECRET_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "SENTINELX_BOOTSTRAP_ADMIN_USERNAME": "replacement-admin",
                    "SENTINELX_BOOTSTRAP_ADMIN_PASSWORD": "ReplacementPass!12",
                    "BOOTSTRAP_ADMIN_USERNAME": "",
                    "BOOTSTRAP_ADMIN_PASSWORD": "",
                },
                clear=True,
            ):
                preserved = ensure_bootstrap_administrator()
                self.assertEqual(preserved.id, existing_admin.id)
                self.assertTrue(existing_admin.check_password("ExistingPassword!12"))
                self.assertIsNone(
                    User.query.filter_by(username="replacement-admin").first()
                )

        with patch.object(AppConfig, "ENV", "development", create=True):
            with patch.dict(
                os.environ,
                {
                    "SENTINELX_ENV": "development",
                    "BOOTSTRAP_ADMIN_USERNAME": "",
                    "BOOTSTRAP_ADMIN_PASSWORD": "",
                    "SENTINELX_BOOTSTRAP_ADMIN_USERNAME": "",
                    "SENTINELX_BOOTSTRAP_ADMIN_PASSWORD": "",
                },
                clear=True,
            ):
                self.assertIsNone(ensure_bootstrap_administrator())

    def test_session_fixation_and_csrf_protection(self):
        analyst = User(
            username="csrf-analyst",
            email="csrf-analyst@example.com",
            role="security_analyst",
        )
        analyst.set_password("StrongPass!12")
        db.session.add(analyst)
        db.session.commit()

        login = self.client.post(
            "/api/login",
            json={"username": "csrf-analyst", "password": "StrongPass!12"},
        )
        self.assertEqual(login.status_code, 200)

        me = self.client.get("/api/me")
        self.assertEqual(me.status_code, 200)

        csrf_token = me.get_json()["csrf_token"]
        self.assertTrue(csrf_token)

        admin_user = User(
            username="csrf-admin",
            email="csrf-admin@example.com",
            role="administrator",
        )
        admin_user.set_password("AdminPass!88")
        db.session.add(admin_user)
        db.session.commit()

        self.client.post("/api/logout")

        admin_login = self.client.post(
            "/api/login",
            json={"username": "csrf-admin", "password": "AdminPass!88"},
        )
        self.assertEqual(admin_login.status_code, 200)

        admin_me = self.client.get("/api/me")
        self.assertEqual(admin_me.status_code, 200)

        admin_csrf_token = admin_me.get_json()["csrf_token"]
        self.assertTrue(admin_csrf_token)
        self.assertNotEqual(csrf_token, admin_csrf_token)

        no_token_response = self.client.post(
            "/api/sources",
            json={"name": "csrf-source", "source_type": "linux"},
        )
        self.assertEqual(no_token_response.status_code, 403)
        self.assertIn("CSRF token missing or invalid", no_token_response.get_data(as_text=True))

        invalid_token_response = self.client.post(
            "/api/sources",
            json={"name": "csrf-source", "source_type": "linux"},
            headers={"X-CSRFToken": "bad-token"},
        )
        self.assertEqual(invalid_token_response.status_code, 403)
        self.assertIn("CSRF token missing or invalid", invalid_token_response.get_data(as_text=True))

        valid_token_response = self.client.post(
            "/api/sources",
            json={"name": "csrf-source", "source_type": "linux"},
            headers={"X-CSRFToken": admin_csrf_token},
        )
        self.assertEqual(valid_token_response.status_code, 201)
        self.assertIn("Source registered successfully", valid_token_response.get_data(as_text=True))

    def test_inactive_account_cannot_authenticate(self):
        user = User(
            username="inactive-user",
            email="inactive-user@example.com",
            role="security_analyst",
            status="inactive",
        )
        user.set_password("StrongPass!12")
        db.session.add(user)
        db.session.commit()

        response = self.client.post(
            "/api/login",
            json={"username": "inactive-user", "password": "StrongPass!12"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("inactive", response.get_json()["error"].lower())

    def test_protected_routes_reject_unauthenticated_requests(self):
        unauthenticated = self.client.get("/api/me")
        self.assertEqual(unauthenticated.status_code, 401)

        forbidden_admin = self.client.get("/api/admin/users")
        self.assertEqual(forbidden_admin.status_code, 401)

        no_login_sources = self.client.post(
            "/api/sources",
            json={"name": "ops-linux-host", "source_type": "linux"},
        )
        self.assertEqual(no_login_sources.status_code, 401)

        no_login_agents = self.client.post(
            "/api/agents",
            json={"agent_id": "agent-001", "name": "TestAgent"},
        )
        self.assertEqual(no_login_agents.status_code, 401)

    def test_source_management_and_duplicate_rejection(self):
        admin_user = User(username="sourceadmin", role="administrator")
        admin_user.set_password("Secret!12")

        analyst = User(username="nonadmin", role="security_analyst")
        analyst.set_password("Secret!34")

        db.session.add_all([admin_user, analyst])
        db.session.commit()

        login = self.client.post(
            "/api/login",
            json={"username": "nonadmin", "password": "Secret!34"},
        )
        self.assertEqual(login.status_code, 200)

        unauthorized = self.client.post(
            "/api/sources",
            json={"name": "ops-linux-host", "source_type": "linux", "status": "active", "metadata": {"host": "ops-linux-host"}},
        )
        self.assertEqual(unauthorized.status_code, 403)

        self.client.post("/api/logout")

        admin_login = self.client.post(
            "/api/login",
            json={"username": "sourceadmin", "password": "Secret!12"},
        )
        self.assertEqual(admin_login.status_code, 200)

        csrf_headers = {"X-CSRFToken": self.client.get("/api/me").get_json()["csrf_token"]}

        response = self.client.post(
            "/api/sources",
            json={"name": "ops-linux-host", "source_type": "linux", "status": "active", "metadata": {"host": "ops-linux-host"}},
            headers=csrf_headers,
        )
        self.assertEqual(response.status_code, 201)

        duplicate = self.client.post(
            "/api/sources",
            json={"name": "ops-linux-host", "source_type": "linux", "metadata": {"host": "ops-linux-host"}},
            headers=csrf_headers,
        )
        self.assertEqual(duplicate.status_code, 409)

        sources = self.client.get("/api/sources")
        data = sources.get_json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["sources"][0]["source_type"], "linux")

    def test_agent_registration_health_monitoring(self):
        admin_user = User(username="agentadmin", role="administrator")
        admin_user.set_password("AgentPass!22")

        analyst = User(username="agentviewer", role="security_analyst")
        analyst.set_password("ViewerPass!22")

        db.session.add_all([admin_user, analyst])
        db.session.commit()

        self.client.post(
            "/api/login",
            json={"username": "agentviewer", "password": "ViewerPass!22"},
        )

        forbidden = self.client.post(
            "/api/agents",
            json={
                "agent_id": "agent-003",
                "name": "ThreatHunterA",
                "role": "security_analyst",
                "status": "active",
                "health": "healthy",
                "metadata": {"host": "edge-node"},
                "security_policy": {"allowed_actions": ["collect_evidence", "select_tool"]},
            },
        )
        self.assertEqual(forbidden.status_code, 403)

        self.client.post("/api/logout")

        self.client.post(
            "/api/login",
            json={"username": "agentadmin", "password": "AgentPass!22"},
        )
        admin_csrf = {"X-CSRFToken": self.client.get("/api/me").get_json()["csrf_token"]}

        response = self.client.post(
            "/api/agents",
            json={
                "agent_id": "agent-003",
                "name": "ThreatHunterA",
                "role": "security_analyst",
                "status": "active",
                "health": "healthy",
                "metadata": {"host": "edge-node"},
                "security_policy": {"allowed_actions": ["collect_evidence", "select_tool"]},
            },
            headers=admin_csrf,
        )
        self.assertEqual(response.status_code, 201)

        agent_payload = response.get_json()["agent"]
        self.assertEqual(agent_payload["agent_id"], "agent-003")
        self.assertEqual(agent_payload["health"], "healthy")

        self.client.post("/api/logout")

        self.client.post(
            "/api/login",
            json={"username": "agentviewer", "password": "ViewerPass!22"},
        )
        analyst_csrf = {"X-CSRFToken": self.client.get("/api/me").get_json()["csrf_token"]}

        forbidden_patch = self.client.patch(
            "/api/agents/1",
            json={"health": "critical"},
            headers=analyst_csrf,
        )
        self.assertEqual(forbidden_patch.status_code, 403)

        self.client.post("/api/logout")

        self.client.post(
            "/api/login",
            json={"username": "agentadmin", "password": "AgentPass!22"},
        )
        admin_csrf = {"X-CSRFToken": self.client.get("/api/me").get_json()["csrf_token"]}

        heartbeat = self.client.post(
            "/api/agents/agent-003/heartbeat",
            json={"health": "degraded"},
            headers=admin_csrf,
        )
        self.assertEqual(heartbeat.status_code, 200)
        self.assertEqual(heartbeat.get_json()["agent"]["health"], "degraded")

    def test_tool_selection_and_evidence_gap_analysis(self):
        incident = {
            "event_type": "failed_login",
            "username": "dsmith",
            "source_ip": "10.9.9.44",
            "hostname": "web-04",
        }

        selection = select_next_best_tool(
            incident,
            evidence=[],
            context={},
            available_tools=None,
        )
        self.assertIn("selected_tool", selection)
        self.assertGreaterEqual(selection["selection_score"], 0.0)
        self.assertLessEqual(selection["selection_score"], 1.0)
        self.assertIn("Authentication log review", selection["selected_tool"])
        self.assertTrue(selection["evidence_gap_addressed"])
        self.assertIn("risk_level", selection)
        self.assertTrue(selection["alternative_tools"])

        missing = identify_missing_evidence(incident, evidence=[])
        self.assertTrue(any(item["type"] == "failed_login" for item in missing))
        self.assertTrue(any(item["type"] == "network_telemetry" for item in missing))

    def test_nbe_handles_empty_tools(self):
        incident = {
            "event_type": "failed_login",
            "username": "dsmith",
            "source_ip": "10.9.9.44",
        }

        result = select_next_best_tool(
            incident,
            evidence=[],
            available_tools=[],
        )
        self.assertIsNone(result["selected_tool"])
        self.assertEqual(result["selection_score"], 0.0)

    def test_investigation_pipeline_integration(self):
        self.client.post(
            "/api/register",
            json={"username": "ops", "password": "OpsPass!44", "role": "administrator"},
        )
        self.client.post(
            "/api/login",
            json={"username": "ops", "password": "OpsPass!44"},
        )
        csrf_headers = {"X-CSRFToken": self.client.get("/api/me").get_json()["csrf_token"]}

        response = self.client.post(
            "/api/investigation/tool-selection",
            json={
                "incident": {
                    "event_type": "failed_login",
                    "username": "ops",
                    "source_ip": "10.2.2.1",
                },
                "context": {"window_minutes": 30},
                "failed_tools": [],
            },
            headers=csrf_headers,
        )
        self.assertEqual(response.status_code, 200)

        payload = response.get_json()
        self.assertIn("selected_tool", payload)
        self.assertIn("selection_reason", payload)
        self.assertIn("next_recommended_investigation_action", payload)

        investigation_response = self.client.post(
            "/api/investigation",
            json={
                "incident": {"event_type": "failed_login", "username": "ops", "source_ip": "10.2.2.1"},
                "context": {"window_minutes": 30},
            },
            headers=csrf_headers,
        )
        self.assertEqual(investigation_response.status_code, 200)
        investigation_payload = investigation_response.get_json()
        self.assertIn("tool_selection", investigation_payload)
        self.assertIn("missing_evidence", investigation_payload)


if __name__ == "__main__":
    unittest.main()
