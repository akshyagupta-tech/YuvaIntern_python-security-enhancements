"""Backward-compatible authentication facade over hardened modules."""

from __future__ import annotations

from pathlib import Path

from crypto import PasswordHasher
from database import Database
from sanitizer import InputSanitizer
from security_errors import InputValidationError
from subprocess_runner import safe_network_ping

SecurityValidationError = InputValidationError


class SecureAuth:
    """Preserve the legacy API while storing only salted PBKDF2 credentials."""

    SALT_BYTES = PasswordHasher.SALT_BYTES
    PBKDF2_ITERATIONS = PasswordHasher.PBKDF2_ITERATIONS

    def __init__(self, database_path: str | Path) -> None:
        self.database = Database(database_path)
        self.hasher = PasswordHasher()
        self.sanitizer = InputSanitizer()
        self._legacy_roles: dict[str, str] = {}

    def initialize_database(self) -> None:
        """Create the schema without truncating existing account data."""
        self.database.initialize()

    @classmethod
    def _hash_password(cls, password: str, salt: bytes) -> bytes:
        """Legacy helper retained for callers with pre-generated raw salts."""
        import hashlib

        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            cls.PBKDF2_ITERATIONS,
        )

    def register_user(
        self,
        username: str,
        password: str,
        role: str = "user",
    ) -> None:
        """Create a user using the hardened credential and DB layers."""
        clean_username = self.sanitizer.validate_username(username)
        normalized_roles = {
            "admin": "Administrator",
            "user": "Viewer",
        }
        database_role = normalized_roles.get(role, role)
        salt, password_hash = self.hasher.hash_password(password)
        self.database.create_user(
            clean_username,
            salt,
            password_hash,
            database_role,
        )
        self._legacy_roles[clean_username] = role

    def authenticate(self, username: str, password: str) -> str | None:
        """Authenticate through parameterized lookup and constant-time verify."""
        try:
            clean_username = self.sanitizer.validate_username(username)
        except InputValidationError:
            return None
        user = self.database.get_user(clean_username)
        if user is None or not self.hasher.verify_password(
            password,
            user.salt,
            user.password_hash,
        ):
            return None
        return self._legacy_roles.get(clean_username, user.role)


__all__ = ["SecureAuth", "SecurityValidationError", "safe_network_ping"]
