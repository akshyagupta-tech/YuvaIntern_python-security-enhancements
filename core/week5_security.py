"""Defensive authentication, rate limiting, and host validation helpers."""

from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
import subprocess
import tempfile
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Deque, Dict, Optional, Tuple, Union


class SecurityValidationError(ValueError):
    """Raised when input does not match the permitted security policy."""


@dataclass(frozen=True)
class SessionRecord:
    """Represent an authenticated session and its expiration time."""

    username: str
    role: str
    expires_at: float


_DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\Z"
)
_IPV4_PATTERN = re.compile(
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}\Z"
)


class SecurityEngine:
    """Manage parameterized authentication and in-memory security controls."""

    SALT_BYTES = 16
    PBKDF2_ITERATIONS = 100_000
    MAX_FAILED_ATTEMPTS = 5
    RATE_LIMIT_WINDOW_SECONDS = 60
    SESSION_TTL_SECONDS = 1_800

    def __init__(self, database_path: Union[str, Path]) -> None:
        self.database_path = str(database_path)
        self._failed_attempts: Dict[str, Deque[float]] = {}
        self._active_sessions: Dict[str, SessionRecord] = {}
        self._audit_log: Deque[str] = deque(maxlen=200)
        self._lock = RLock()

    @classmethod
    def hash_password(cls, password: str) -> Tuple[str, str]:
        """Return a PBKDF2 hash and a random 16-byte salt encoded as hex."""
        if not isinstance(password, str) or not password:
            raise SecurityValidationError(
                "Password must be a non-empty string."
            )

        salt_hex = secrets.token_hex(cls.SALT_BYTES)
        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            cls.PBKDF2_ITERATIONS,
        ).hex()
        return salt_hex, password_hash

    @classmethod
    def verify_password(
        cls,
        password: str,
        salt_hex: str,
        stored_hash: str,
    ) -> bool:
        """Verify a password with constant-time hash comparison."""
        if not all(
            isinstance(value, str)
            for value in (password, salt_hex, stored_hash)
        ):
            return False
        try:
            salt = bytes.fromhex(salt_hex)
            if len(salt) != cls.SALT_BYTES:
                return False
            candidate_hash = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt,
                cls.PBKDF2_ITERATIONS,
            ).hex()
        except (ValueError, TypeError):
            return False
        return secrets.compare_digest(candidate_hash, stored_hash)

    def initialize_database(self) -> None:
        """Create the user table if it does not already exist."""
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL
                )"""
            )

    def register_user(
        self,
        username: str,
        password: str,
        role: str = "user",
    ) -> None:
        """Store a user with a random salt and parameterized SQL."""
        if not isinstance(username, str) or not re.fullmatch(
            r"[A-Za-z0-9_]{1,64}", username
        ):
            raise SecurityValidationError(
                "Username contains invalid characters."
            )
        if not isinstance(role, str) or not role:
            raise SecurityValidationError("Role must be a non-empty string.")

        salt_hex, password_hash = self.hash_password(password)
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(
                "INSERT INTO users (username, salt, password_hash, role) "
                "VALUES (?, ?, ?, ?)",
                (username, salt_hex, password_hash, role),
            )
        self._record_audit("User registered")

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Authenticate a user, returning their role or None on failure."""
        if (
            not isinstance(username, str)
            or not username
            or len(username) > 128
            or not isinstance(password, str)
        ):
            self._record_audit("Rejected invalid authentication input")
            return None

        rate_key = username.casefold()
        with self._lock:
            if self._is_rate_limited(rate_key):
                self._record_audit("Authentication blocked by rate limit")
                return None

            with sqlite3.connect(self.database_path) as connection:
                row = connection.execute(
                    "SELECT salt, password_hash, role FROM users "
                    "WHERE username = ?",
                    (username,),
                ).fetchone()

            if row is not None:
                salt_hex, stored_hash, role = row
                if self.verify_password(password, salt_hex, stored_hash):
                    self._failed_attempts.pop(rate_key, None)
                    self._record_audit("Authentication succeeded")
                    return role

            self._register_failure(rate_key)
            self._record_audit("Authentication failed")
            return None

    def authenticate_and_create_session(
        self,
        username: str,
        password: str,
    ) -> Optional[str]:
        """Authenticate and create a cryptographically random session token."""
        role = self.authenticate(username, password)
        if role is None:
            return None

        token = secrets.token_urlsafe(32)
        with self._lock:
            self._active_sessions[token] = SessionRecord(
                username=username,
                role=role,
                expires_at=time.monotonic() + self.SESSION_TTL_SECONDS,
            )
        self._record_audit("Session created")
        return token

    def validate_session(self, token: str) -> Optional[SessionRecord]:
        """Return a live session, removing expired or unknown tokens."""
        if not isinstance(token, str):
            return None
        with self._lock:
            session = self._active_sessions.get(token)
            if session is None:
                return None
            if time.monotonic() >= session.expires_at:
                self._active_sessions.pop(token, None)
                self._record_audit("Expired session removed")
                return None
            return session

    def audit_events(self) -> list[str]:
        """Return recent audit events without sensitive values."""
        with self._lock:
            return list(self._audit_log)

    def _is_rate_limited(self, identifier: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.RATE_LIMIT_WINDOW_SECONDS
        recent = deque(
            timestamp
            for timestamp in self._failed_attempts.get(identifier, ())
            if timestamp > cutoff
        )
        if recent:
            self._failed_attempts[identifier] = recent
        else:
            self._failed_attempts.pop(identifier, None)
        return len(recent) >= self.MAX_FAILED_ATTEMPTS

    def _register_failure(self, identifier: str) -> None:
        self._failed_attempts.setdefault(identifier, deque()).append(
            time.monotonic()
        )

    def _record_audit(self, event: str) -> None:
        with self._lock:
            self._audit_log.append(event)

    @staticmethod
    def safe_network_ping(host: str) -> bool:
        """Run one ping only for a strictly whitelisted IPv4 or domain."""
        if not isinstance(host, str) or not (
            _IPV4_PATTERN.fullmatch(host) or _DOMAIN_PATTERN.fullmatch(host)
        ):
            raise SecurityValidationError(
                "Target must be a valid IPv4 or domain."
            )

        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=5,
        )
        return result.returncode == 0


def _get_demo_engine(st: object) -> SecurityEngine:
    """Create a temporary demo database once per Streamlit session."""
    if "week5_security_engine" not in st.session_state:
        database_path = (
            Path(tempfile.gettempdir())
            / f"week5_security_demo_{secrets.token_hex(8)}.sqlite3"
        )
        engine = SecurityEngine(database_path)
        engine.initialize_database()
        engine.register_user("admin", "DemoPassword123!", "admin")
        st.session_state.week5_security_engine = engine
    return st.session_state.week5_security_engine


def _run_streamlit_app() -> None:
    """Render safe SQL/command injection demos and a hash generator."""
    import streamlit as st

    st.title("Application Security Lab")
    engine = _get_demo_engine(st)
    attack_tab, credential_tab = st.tabs(
        ("Attack simulations", "Credential hashing")
    )

    with attack_tab:
        st.caption(
            "Payloads are checked locally; command payloads are never run."
        )
        sql_column, command_column = st.columns(2)
        with sql_column:
            st.subheader("SQL injection")
            st.code("admin' --")
            if st.button("Simulate SQL injection", key="week5_sql_payload"):
                role = engine.authenticate("admin' --", "not-a-password")
                if role is None:
                    st.success("Blocked: the payload matched no account.")
                else:
                    st.error("Unexpected authentication result.")
        with command_column:
            st.subheader("Command injection")
            st.code("127.0.0.1; whoami")
            if st.button(
                "Simulate command injection",
                key="week5_command_payload",
            ):
                try:
                    SecurityEngine.safe_network_ping("127.0.0.1; whoami")
                except SecurityValidationError:
                    engine._record_audit("Rejected command injection payload")
                    st.success("Blocked before subprocess execution.")
                else:
                    st.error("Unexpected validation result.")

        st.subheader("Recent audit events")
        events = engine.audit_events()
        st.code("\n".join(events) if events else "No events yet.")

    with credential_tab:
        password = st.text_input("Password to hash", type="password")
        if st.button("Generate PBKDF2 hash", key="week5_hash_password"):
            try:
                salt_hex, password_hash = SecurityEngine.hash_password(
                    password
                )
            except SecurityValidationError as error:
                st.error(str(error))
            else:
                st.json(
                    {
                        "algorithm": "PBKDF2-HMAC-SHA256",
                        "iterations": SecurityEngine.PBKDF2_ITERATIONS,
                        "salt_hex": salt_hex,
                        "password_hash": password_hash,
                    }
                )


if __name__ == "__main__":
    _run_streamlit_app()
