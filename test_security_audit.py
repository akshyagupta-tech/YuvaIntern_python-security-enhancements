"""Compatibility regressions for the Week 5 security facade."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from audit import AuditLogger
from auth import AuthenticationService
from database import Database
from security_errors import InputValidationError
from sessions import Role
from subprocess_runner import safe_network_ping
from vulnerable_auth_app import comparison_examples


class TestSecurityFacadeRegressions(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        database = Database(Path(self.temp_directory.name) / "users.sqlite3")
        database.initialize()
        self.audit = AuditLogger()
        self.service = AuthenticationService(database, audit=self.audit)
        self.service.register_user(
            "admin", "AdminPassword-12345", Role.ADMINISTRATOR
        )
        self.service.register_user(
            "alice", "AlicePassword-12345", Role.OPERATOR
        )

    def tearDown(self) -> None:
        self.temp_directory.cleanup()

    def test_comparison_examples_are_inert_and_document_the_controls(
        self,
    ) -> None:
        examples = comparison_examples()
        self.assertGreaterEqual(len(examples), 3)
        self.assertTrue(
            all("defensive_control" in example for example in examples)
        )

    def test_injection_payload_is_rejected_by_hardened_authentication(
        self,
    ) -> None:
        self.assertIsNone(
            self.service.login("admin' --", "irrelevant-password")
        )
        self.assertEqual(
            self.service.login("admin", "AdminPassword-12345", "192.0.2.1")
            is not None,
            True,
        )

    def test_command_payload_is_rejected_before_process_execution(
        self,
    ) -> None:
        with patch("subprocess_runner.subprocess.run") as run:
            with self.assertRaises(InputValidationError):
                safe_network_ping("127.0.0.1; whoami")
        run.assert_not_called()

    def test_repeated_bad_passwords_throttle_correct_login(self) -> None:
        for _ in range(5):
            self.assertIsNone(
                self.service.login("alice", "incorrect-password", "192.0.2.2")
            )
        self.assertIsNone(
            self.service.login("alice", "AlicePassword-12345", "192.0.2.2")
        )

    def test_successful_login_issues_session_and_audit_event(self) -> None:
        credentials = self.service.login(
            "admin", "AdminPassword-12345", "192.0.2.3"
        )
        self.assertIsNotNone(credentials)
        session = self.service.sessions.validate(credentials.session_token)
        self.assertEqual(session.role, Role.ADMINISTRATOR)
        self.assertTrue(self.audit.verify_chain())


if __name__ == "__main__":
    unittest.main()
