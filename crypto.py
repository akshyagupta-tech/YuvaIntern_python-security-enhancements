"""Password hashing and cryptographically secure secret generation."""

from __future__ import annotations

import hashlib
import secrets
from typing import TypeAlias

from security_errors import InputValidationError

PasswordInput: TypeAlias = str | bytearray


class PasswordHasher:
    """Derive password hashes using salted PBKDF2-HMAC-SHA256."""

    SALT_BYTES = 16
    PBKDF2_ITERATIONS = 100_000
    DIGEST_BYTES = 32

    def __init__(self, iterations: int = PBKDF2_ITERATIONS) -> None:
        if isinstance(iterations, bool) or not isinstance(iterations, int):
            raise InputValidationError("Hash iterations must be an integer.")
        if iterations < self.PBKDF2_ITERATIONS:
            raise InputValidationError(
                "Hash iterations cannot be below the configured security floor."
            )
        self.iterations = iterations

    @classmethod
    def _password_buffer(cls, password: PasswordInput) -> bytearray:
        if isinstance(password, bytearray):
            if not password:
                raise InputValidationError("Password must not be empty.")
            return password
        if not isinstance(password, str) or not password:
            raise InputValidationError("Password must be a non-empty string.")
        return bytearray(password.encode("utf-8"))

    @staticmethod
    def _scrub(buffer: bytearray) -> None:
        buffer[:] = b"\x00" * len(buffer)

    def hash_password(self, password: PasswordInput) -> tuple[str, str]:
        """Return hex salt and digest, scrubbing the mutable working buffer."""
        password_buffer = self._password_buffer(password)
        salt_hex = secrets.token_hex(self.SALT_BYTES)
        try:
            digest = hashlib.pbkdf2_hmac(
                "sha256",
                password_buffer,
                bytes.fromhex(salt_hex),
                self.iterations,
                dklen=self.DIGEST_BYTES,
            )
            return salt_hex, digest.hex()
        finally:
            self._scrub(password_buffer)

    def verify_password(
        self,
        password: PasswordInput,
        salt_hex: str,
        stored_digest_hex: str,
    ) -> bool:
        """Verify a candidate using constant-time digest comparison."""
        if not isinstance(salt_hex, str) or not isinstance(
            stored_digest_hex, str
        ):
            return False
        try:
            salt = bytes.fromhex(salt_hex)
            expected_digest = bytes.fromhex(stored_digest_hex)
        except ValueError:
            return False
        if (
            len(salt) != self.SALT_BYTES
            or len(expected_digest) != self.DIGEST_BYTES
        ):
            return False
        try:
            password_buffer = self._password_buffer(password)
        except InputValidationError:
            return False
        try:
            candidate = hashlib.pbkdf2_hmac(
                "sha256",
                password_buffer,
                salt,
                self.iterations,
                dklen=self.DIGEST_BYTES,
            ).hex()
            return secrets.compare_digest(candidate, stored_digest_hex)
        finally:
            self._scrub(password_buffer)


def hash_password(password: PasswordInput) -> tuple[str, str]:
    """Module-level convenience wrapper using the mandated iteration count."""
    return PasswordHasher().hash_password(password)


def verify_password(
    password: PasswordInput,
    salt_hex: str,
    stored_digest_hex: str,
) -> bool:
    """Module-level convenience wrapper for constant-time verification."""
    return PasswordHasher().verify_password(
        password, salt_hex, stored_digest_hex
    )


def generate_session_token() -> str:
    """Generate a cryptographically secure opaque session token."""
    return secrets.token_urlsafe(32)


def generate_csrf_token() -> str:
    """Generate an independent cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)


def generate_api_key() -> str:
    """Generate a high-entropy URL-safe API authentication key."""
    return secrets.token_urlsafe(48)


__all__ = [
    "PasswordHasher",
    "generate_api_key",
    "generate_csrf_token",
    "generate_session_token",
    "hash_password",
    "verify_password",
]
