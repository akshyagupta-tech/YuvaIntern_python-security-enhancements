"""Security regression tests for the Week 5 hardening module."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.week5_security import SecurityEngine, SecurityValidationError


class TestSecurityEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "users.sqlite3"
        self.engine = SecurityEngine(self.database_path)
        self.engine.initialize_database()
        self.engine.register_user(
            "admin",
            "CorrectHorseBatteryStaple",
            "admin",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_sql_injection_payload_is_treated_as_username_data(self) -> None:
        self.assertIsNone(self.engine.authenticate("admin' --", "ignored"))
        self.assertEqual(
            self.engine.authenticate("admin", "CorrectHorseBatteryStaple"),
            "admin",
        )
        with sqlite3.connect(self.database_path) as connection:
            usernames = connection.execute(
                "SELECT username FROM users"
            ).fetchall()
        self.assertEqual(usernames, [("admin",)])

    def test_password_hash_uses_random_16_byte_salt_and_verifies(self) -> None:
        salt_a, hash_a = SecurityEngine.hash_password("same-password")
        salt_b, hash_b = SecurityEngine.hash_password("same-password")

        self.assertEqual(len(bytes.fromhex(salt_a)), 16)
        self.assertNotEqual(salt_a, salt_b)
        self.assertNotEqual(hash_a, hash_b)
        self.assertTrue(
            SecurityEngine.verify_password("same-password", salt_a, hash_a)
        )
        self.assertFalse(
            SecurityEngine.verify_password("wrong-password", salt_a, hash_a)
        )

    def test_command_payload_is_rejected_before_subprocess(self) -> None:
        with patch("core.week5_security.subprocess.run") as run:
            with self.assertRaises(SecurityValidationError):
                SecurityEngine.safe_network_ping("127.0.0.1; whoami")

        run.assert_not_called()

    def test_valid_host_uses_non_shell_argument_vector(self) -> None:
        with patch("core.week5_security.subprocess.run") as run:
            run.return_value.returncode = 0
            self.assertTrue(SecurityEngine.safe_network_ping("127.0.0.1"))

        run.assert_called_once_with(
            ["ping", "-c", "1", "127.0.0.1"],
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=5,
        )

    def test_failed_attempts_are_limited_with_a_sliding_window(self) -> None:
        with patch("core.week5_security.time.monotonic", return_value=100.0):
            with patch.object(
                SecurityEngine,
                "verify_password",
                return_value=False,
            ):
                for _ in range(SecurityEngine.MAX_FAILED_ATTEMPTS):
                    self.assertIsNone(
                        self.engine.authenticate("admin", "wrong")
                    )
                self.assertIsNone(
                    self.engine.authenticate(
                        "admin",
                        "CorrectHorseBatteryStaple",
                    )
                )

        with patch("core.week5_security.time.monotonic", return_value=161.0):
            self.assertEqual(
                self.engine.authenticate("admin", "CorrectHorseBatteryStaple"),
                "admin",
            )

    def test_session_token_is_secure_and_validated(self) -> None:
        token = self.engine.authenticate_and_create_session(
            "admin",
            "CorrectHorseBatteryStaple",
        )

        self.assertIsNotNone(token)
        self.assertGreaterEqual(len(token), 40)
        session = self.engine.validate_session(token)
        self.assertIsNotNone(session)
        self.assertEqual(session.username, "admin")
        self.assertEqual(session.role, "admin")
        self.assertIsNone(self.engine.validate_session("invalid-token"))


if __name__ == "__main__":
    unittest.main()
