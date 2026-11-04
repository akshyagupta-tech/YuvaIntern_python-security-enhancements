"""Regression tests for the Enterprise Defensive Security suite."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from audit import AuditLogger
from auth import AuthenticationService
from crypto import PasswordHasher, generate_api_key, generate_csrf_token
from database import Database
from rate_limiter import TokenBucketRateLimiter
from sanitizer import InputSanitizer
from security_checks import scan_project, scan_source
from security_errors import (
    AuthorizationError,
    InputValidationError,
    public_error,
)
from sessions import Role, SessionManager
from subprocess_runner import safe_network_ping


class TestPasswordCryptography(unittest.TestCase):
    def test_password_hash_uses_100000_pbkdf2_rounds_and_random_16_byte_salt(
        self,
    ) -> None:
        hasher = PasswordHasher()
        salt_a, digest_a = hasher.hash_password("correct horse battery staple")
        salt_b, digest_b = hasher.hash_password("correct horse battery staple")
        self.assertEqual(hasher.iterations, 100_000)
        self.assertEqual(len(bytes.fromhex(salt_a)), 16)
        self.assertNotEqual(salt_a, salt_b)
        self.assertNotEqual(digest_a, digest_b)
        self.assertTrue(
            hasher.verify_password(
                "correct horse battery staple", salt_a, digest_a
            )
        )
        self.assertFalse(
            hasher.verify_password("wrong password", salt_a, digest_a)
        )

    def test_salt_uses_secrets_token_hex_and_verification_is_constant_time(
        self,
    ) -> None:
        with patch(
            "crypto.secrets.token_hex", return_value="ab" * 16
        ) as token_hex:
            salt, digest = PasswordHasher().hash_password(
                "a long test password"
            )
        token_hex.assert_called_once_with(16)
        self.assertEqual(salt, "ab" * 16)
        with patch(
            "crypto.secrets.compare_digest", return_value=True
        ) as compare:
            self.assertTrue(
                PasswordHasher().verify_password(
                    "a long test password", salt, digest
                )
            )
        compare.assert_called_once()

    def test_mutable_raw_password_buffer_is_scrubbed(self) -> None:
        password_buffer = bytearray(b"temporary password material")
        PasswordHasher().hash_password(password_buffer)
        self.assertEqual(password_buffer, bytearray(len(password_buffer)))

    def test_malformed_hash_inputs_fail_closed(self) -> None:
        self.assertFalse(
            PasswordHasher().verify_password("password", "bad", "bad")
        )

    def test_secret_generators_return_distinct_tokens(self) -> None:
        self.assertNotEqual(generate_csrf_token(), generate_csrf_token())
        self.assertNotEqual(generate_api_key(), generate_api_key())


class TestDatabaseAndSanitization(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "security.sqlite3"
        self.database = Database(self.database_path)
        self.database.initialize()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_parameterized_database_stores_special_password_as_data(
        self,
    ) -> None:
        hasher = PasswordHasher()
        salt, digest = hasher.hash_password(
            "quote ' OR 1=1 -- ; DROP TABLE users"
        )
        self.database.create_user("alice", salt, digest, Role.OPERATOR.value)
        record = self.database.get_user("alice")
        self.assertIsNotNone(record)
        self.assertTrue(
            hasher.verify_password(
                "quote ' OR 1=1 -- ; DROP TABLE users",
                record.salt,
                record.password_hash,
            )
        )
        self.assertEqual(self.database.user_count(), 1)
        with sqlite3.connect(self.database.path) as connection:
            self.assertIsNotNone(
                connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = ? AND name = ?",
                    ("table", "users"),
                ).fetchone()
            )

    def test_username_injection_payload_does_not_match_an_account(
        self,
    ) -> None:
        self.assertIsNone(self.database.get_user("' OR 1=1 --"))
        self.assertEqual(self.database.user_count(), 0)

    def test_in_memory_database_persists_across_repository_connections(
        self,
    ) -> None:
        database = Database(":memory:")
        try:
            database.initialize()
            database.create_user(
                "alice", "ab" * 16, "cd" * 32, Role.VIEWER.value
            )
            self.assertEqual(database.user_count(), 1)
        finally:
            database.close()

    def test_reinitializing_database_does_not_delete_users(self) -> None:
        self.database.create_user(
            "alice", "ab" * 16, "cd" * 32, Role.VIEWER.value
        )
        self.database.initialize()
        self.assertEqual(self.database.user_count(), 1)

    def test_sanitizer_normalizes_unicode_and_removes_markup(self) -> None:
        sanitizer = InputSanitizer()
        result = sanitizer.sanitize_text(
            "<b>Ａlice</b><script>alert(1)</script>"
        )
        self.assertEqual(result, "Alice")

    def test_sanitizer_rejects_non_whitelisted_characters(self) -> None:
        with self.assertRaises(InputValidationError):
            InputSanitizer().validate_username("user; DROP TABLE users")

    def test_sanitizer_rejects_oversized_input(self) -> None:
        with self.assertRaises(InputValidationError):
            InputSanitizer(max_length=8).sanitize_text("x" * 9)


class TestSubprocessAndErrors(unittest.TestCase):
    def test_injection_host_is_rejected_before_subprocess(self) -> None:
        with patch("subprocess_runner.subprocess.run") as run:
            with self.assertRaises(InputValidationError):
                safe_network_ping("127.0.0.1; whoami")
        run.assert_not_called()

    def test_valid_host_uses_argv_no_shell_and_timeout(self) -> None:
        with patch("subprocess_runner.subprocess.run") as run:
            run.return_value.returncode = 0
            self.assertTrue(safe_network_ping("127.0.0.1"))
        run.assert_called_once_with(
            ["ping", "-c", "1", "127.0.0.1"],
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=3,
        )

    def test_nonfinite_timeout_is_rejected_before_subprocess(self) -> None:
        with patch("subprocess_runner.subprocess.run") as run:
            with self.assertRaises(ValueError):
                safe_network_ping("127.0.0.1", float("nan"))
        run.assert_not_called()

    def test_public_errors_hide_internal_details(self) -> None:
        error = InputValidationError(
            "Rejected", context={"path": "/secret/db.sqlite"}
        )
        response = public_error(error)
        self.assertEqual(response["code"], "SEC-400")
        self.assertNotIn("/secret/db.sqlite", json.dumps(response))
        self.assertEqual(
            public_error(RuntimeError("schema users leaked"))["code"],
            "SEC-500",
        )


class TestSessionsAndRateLimiting(unittest.TestCase):
    def test_role_permissions_and_escalation_denial(self) -> None:
        sessions = SessionManager()
        credentials = sessions.create_session("alice", Role.VIEWER)
        self.assertTrue(
            sessions.require_permission(
                credentials.session_token, "read:dashboard"
            )
        )
        with self.assertRaises(AuthorizationError):
            sessions.require_permission(
                credentials.session_token, "users:write"
            )

    def test_session_expiration_and_csrf_binding(self) -> None:
        sessions = SessionManager(ttl_seconds=10)
        with patch(
            "sessions.time.monotonic", side_effect=[100.0, 105.0, 111.0]
        ):
            credentials = sessions.create_session("alice", Role.OPERATOR)
            self.assertTrue(
                sessions.validate_csrf(
                    credentials.session_token, credentials.csrf_token
                )
            )
            self.assertIsNone(sessions.validate(credentials.session_token))

    def test_token_bucket_enforces_exponential_lockout(self) -> None:
        limiter = TokenBucketRateLimiter(
            capacity=3,
            refill_rate_per_second=1.0,
            lockout_threshold=2,
            base_lockout_seconds=2.0,
            max_lockout_seconds=8.0,
        )
        with patch("rate_limiter.time.monotonic", return_value=100.0):
            limiter.record_failure("user:alice")
            limiter.record_failure("user:alice")
            limiter.record_failure("user:alice")
            self.assertEqual(limiter.retry_after("user:alice"), 4.0)
        with patch("rate_limiter.time.monotonic", return_value=101.0):
            self.assertFalse(limiter.is_allowed("user:alice"))

    def test_authentication_tracks_user_and_ip_and_creates_scoped_session(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "auth.sqlite3")
            database.initialize()
            audit = AuditLogger()
            service = AuthenticationService(database, audit=audit)
            service.register_user(
                "alice", "A-strong-password-123", Role.OPERATOR
            )
            credentials = service.login(
                "alice", "A-strong-password-123", "192.0.2.4"
            )
            self.assertIsNotNone(credentials)
            self.assertTrue(
                service.sessions.require_permission(
                    credentials.session_token, "diagnostics:run"
                )
            )
            self.assertTrue(audit.verify_chain())


class TestAuditAndStaticChecks(unittest.TestCase):
    def test_audit_masks_sensitive_fields_and_detects_tampering(self) -> None:
        audit = AuditLogger(hmac_key=b"test-integrity-key" * 2)
        audit.log(
            "authentication_failed",
            details={
                "password": "never-log-this",
                "api_key": "secret-key-value",
                "note": "Bearer token-value",
            },
        )
        records = audit.records()
        serialized = json.dumps(records)
        self.assertNotIn("never-log-this", serialized)
        self.assertNotIn("secret-key-value", serialized)
        self.assertTrue(audit.verify_chain(records))
        records[0]["event"] = "tampered"
        self.assertFalse(audit.verify_chain(records))

    def test_jsonl_export_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "audit.jsonl"
            audit = AuditLogger(hmac_key=b"x" * 32)
            audit.log("login", details={"password": "plain-secret"})
            audit.write_jsonl(destination)
            self.assertNotIn(
                "plain-secret", destination.read_text(encoding="utf-8")
            )

    def test_ast_scanner_detects_unsafe_calls_imports_and_keys(self) -> None:
        source = (
            "import pickle\nAPI_KEY = 'abcdefghijklmno123456'\neval('1')\n"
        )
        findings = scan_source(source, "sample.py")
        rules = {finding.rule for finding in findings}
        self.assertIn("SEC-STATIC-UNSAFE-IMPORT", rules)
        self.assertIn("SEC-STATIC-DYNAMIC-EVAL", rules)
        self.assertIn("SEC-STATIC-HARDCODED-SECRET", rules)

    def test_ast_scanner_detects_aliased_unsafe_calls(self) -> None:
        source = (
            "from builtins import eval as run_code\n"
            "from subprocess import run as invoke\n"
            "run_code('1')\n"
            "invoke(['tool'], shell=True)\n"
            "PASSWORD = 'hardcoded-password-value'\n"
        )
        rules = {finding.rule for finding in scan_source(source)}
        self.assertIn("SEC-STATIC-DYNAMIC-EVAL", rules)
        self.assertIn("SEC-STATIC-SHELL-TRUE", rules)
        self.assertIn("SEC-STATIC-HARDCODED-SECRET", rules)

    def test_project_integrity_scan_is_clean(self) -> None:
        project_root = Path(__file__).resolve().parent
        self.assertEqual(scan_project(project_root), [])


if __name__ == "__main__":
    unittest.main()
