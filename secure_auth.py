"""Small defensive authentication and host-probing helpers."""

from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
import subprocess
from pathlib import Path
from typing import Optional


class SecurityValidationError(ValueError):
    """Raised when input does not match the permitted host format."""


class SecureAuth:
    """SQLite-backed authentication using parameterized SQL and PBKDF2."""

    SALT_BYTES = 16
    PBKDF2_ITERATIONS = 600_000

    def __init__(self, database_path: str | Path):
        self.database_path = str(database_path)

    def initialize_database(self) -> None:
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    role TEXT NOT NULL
                )"""
            )

    @classmethod
    def _hash_password(cls, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            cls.PBKDF2_ITERATIONS,
        )

    def register_user(self, username: str, password: str, role: str = "user") -> None:
        salt = secrets.token_bytes(self.SALT_BYTES)
        password_hash = self._hash_password(password, salt)
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(
                "INSERT INTO users (username, salt, password_hash, role) VALUES (?, ?, ?, ?)",
                (username, salt, password_hash, role),
            )

    def authenticate(self, username: str, password: str) -> Optional[str]:
        with sqlite3.connect(self.database_path) as connection:
            row = connection.execute(
                "SELECT salt, password_hash, role FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if row is None:
            return None

        salt, stored_hash, role = row
        candidate_hash = self._hash_password(password, salt)
        return role if secrets.compare_digest(candidate_hash, stored_hash) else None


_DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\Z"
)
_IPV4_PATTERN = re.compile(
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}\Z"
)


def safe_network_ping(hostname: str) -> bool:
    """Ping a whitelisted host using an argv list rather than a shell string."""
    if not isinstance(hostname, str) or not (
        hostname == "localhost"
        or _DOMAIN_PATTERN.fullmatch(hostname)
        or _IPV4_PATTERN.fullmatch(hostname)
    ):
        raise SecurityValidationError(f"Invalid target address: {hostname!r}")

    result = subprocess.run(
        ["ping", "-c", "1", hostname],
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    return result.returncode == 0