"""Backward-compatible facade for the Week 5 hardened security services."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from audit import AuditLogger
from auth import AuthenticationService
from crypto import PasswordHasher
from database import Database
from security_errors import InputValidationError
from sessions import Role, SessionRecord
from subprocess_runner import safe_network_ping

SecurityValidationError = InputValidationError
DB_FILE = os.environ.get(
    "WEEK5_SECURITY_DATABASE",
    str(Path(tempfile.gettempdir()) / "week5_security_enterprise.sqlite3"),
)


class EnterpriseSecurityEngine:
    """Keep the old class methods while delegating to hardened components."""

    MAX_ATTEMPTS = 5
    LOCKOUT_WINDOW_SECONDS = 60
    SESSION_TTL_SECONDS = 1_800
    _failed_attempts: dict[str, list[float]] = {}
    _service: AuthenticationService | None = None

    @classmethod
    def _get_service(cls) -> AuthenticationService:
        if cls._service is None:
            database = Database(DB_FILE)
            database.initialize()
            audit = AuditLogger()
            cls._service = AuthenticationService(database, audit=audit)
        return cls._service

    @staticmethod
    def hash_password(password: str) -> tuple[str, str]:
        return PasswordHasher().hash_password(password)

    @staticmethod
    def verify_password(password: str, salt: str, stored_hash: str) -> bool:
        return PasswordHasher().verify_password(password, salt, stored_hash)

    @classmethod
    def init_hardened_db(cls, database_path: str | Path | None = None) -> None:
        """Initialize schema only; never reset or seed persistent credentials."""
        global DB_FILE
        if database_path is not None:
            DB_FILE = str(database_path)
        database = Database(DB_FILE)
        database.initialize()
        cls._service = AuthenticationService(database, audit=AuditLogger())

    @classmethod
    def register_user(
        cls,
        username: str,
        password: str,
        role: Role | str = Role.VIEWER,
    ) -> None:
        cls._get_service().register_user(username, password, role)

    @classmethod
    def authenticate_and_create_session(
        cls,
        username: str,
        password: str,
        source_ip: str = "unknown",
    ) -> str | None:
        credentials = cls._get_service().login(username, password, source_ip)
        if credentials is None:
            return None
        return credentials.session_token

    @classmethod
    def authenticate_user(
        cls,
        username: str,
        password: str,
        source_ip: str = "unknown",
    ) -> str | None:
        token = cls.authenticate_and_create_session(
            username, password, source_ip
        )
        if token is None:
            return None
        session = cls.validate_session(token)
        return session.role.value if session else None

    @classmethod
    def validate_session(cls, token: str) -> SessionRecord | None:
        return cls._get_service().sessions.validate(token)

    @classmethod
    def safe_network_ping(cls, hostname: str) -> bool:
        return safe_network_ping(hostname)

    @classmethod
    def audit_events(cls) -> list[dict[str, object]]:
        return cls._get_service().audit_events()


__all__ = [
    "DB_FILE",
    "EnterpriseSecurityEngine",
    "SecurityValidationError",
    "SessionRecord",
]
