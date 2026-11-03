"""Attack simulations for the secure authentication helpers."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secure_auth import (
    SecurityValidationError,
    SecureAuth,
    safe_network_ping,
)


class TestSecurityRemediation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "users.db"
        self.auth = SecureAuth(self.database_path)
        self.auth.initialize_database()
        self.auth.register_user("admin", "CorrectHorseBatteryStaple", "admin")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sql_injection_cannot_bypass_authentication(self):
        self.assertIsNone(self.auth.authenticate("admin' --", "anything"))
        self.assertIsNone(self.auth.authenticate("admin", "' OR 1=1 --"))
        self.assertEqual(
            self.auth.authenticate("admin", "CorrectHorseBatteryStaple"), "admin"
        )

    def test_password_is_stored_as_pbkdf2_hash_with_random_16_byte_salt(self):
        with sqlite3.connect(self.database_path) as connection:
            salt, stored_hash = connection.execute(
                "SELECT salt, password_hash FROM users WHERE username = ?", ("admin",)
            ).fetchone()

        self.assertIsInstance(salt, bytes)
        self.assertEqual(len(salt), 16)
        self.assertIsInstance(stored_hash, bytes)
        self.assertEqual(len(stored_hash), 32)
        self.assertNotEqual(stored_hash, b"CorrectHorseBatteryStaple")
        self.assertIsNone(self.auth.authenticate("admin", "wrong-password"))

    def test_same_password_receives_a_distinct_random_salt(self):
        self.auth.register_user("alice", "shared-password")
        with sqlite3.connect(self.database_path) as connection:
            salts = connection.execute(
                "SELECT salt FROM users WHERE username IN (?, ?)", ("admin", "alice")
            ).fetchall()

        self.assertEqual(len(salts[0][0]), 16)
        self.assertEqual(len(salts[1][0]), 16)
        self.assertNotEqual(salts[0][0], salts[1][0])

    def test_command_injection_payload_is_rejected_before_subprocess(self):
        with patch("secure_auth.subprocess.run") as run:
            with self.assertRaises(SecurityValidationError):
                safe_network_ping("127.0.0.1; echo INJECTED")

        run.assert_not_called()

    def test_valid_host_uses_non_shell_argument_vector(self):
        with patch("secure_auth.subprocess.run") as run:
            run.return_value.returncode = 0
            self.assertTrue(safe_network_ping("127.0.0.1"))

        run.assert_called_once_with(
            ["ping", "-c", "1", "127.0.0.1"],
            capture_output=True,
            text=True,
            check=False,
            shell=False,
        )


if __name__ == "__main__":
    unittest.main()