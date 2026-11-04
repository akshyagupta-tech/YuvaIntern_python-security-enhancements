"""Opaque session lifecycle management and role-based permission scopes."""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from enum import Enum
from threading import RLock

from audit import AuditLogger
from security_errors import AuthorizationError, InputValidationError


class Role(str, Enum):
    VIEWER = "Viewer"
    OPERATOR = "Operator"
    ADMINISTRATOR = "Administrator"


ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.VIEWER: frozenset({"read:dashboard", "read:audit"}),
    Role.OPERATOR: frozenset(
        {"read:dashboard", "read:audit", "diagnostics:run"}
    ),
    Role.ADMINISTRATOR: frozenset(
        {
            "read:dashboard",
            "read:audit",
            "diagnostics:run",
            "users:write",
            "security:configure",
        }
    ),
}


@dataclass(frozen=True)
class SessionCredentials:
    """Raw session/CSRF tokens returned once to the authenticated caller."""

    session_token: str
    csrf_token: str
    expires_at: float


@dataclass(frozen=True)
class SessionRecord:
    """Server-side session state; only token digests are retained as keys."""

    username: str
    role: Role
    expires_at: float
    csrf_digest: str


class SessionManager:
    """Issue opaque sessions, enforce permissions, and lazily expire records."""

    def __init__(
        self,
        ttl_seconds: float = 1_800.0,
        audit: AuditLogger | None = None,
    ) -> None:
        if not isinstance(ttl_seconds, (int, float)) or ttl_seconds <= 0:
            raise InputValidationError("Session TTL must be positive.")
        self.ttl_seconds = float(ttl_seconds)
        self.audit = audit
        self._sessions: dict[str, SessionRecord] = {}
        self._lock = RLock()

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_session(
        self, username: str, role: Role | str
    ) -> SessionCredentials:
        """Create session and CSRF tokens, storing only keyed lookup digests."""
        if not isinstance(username, str) or not username:
            raise InputValidationError("Session username is invalid.")
        try:
            normalized_role = role if isinstance(role, Role) else Role(role)
        except ValueError as error:
            raise InputValidationError("Session role is invalid.") from error
        now = time.monotonic()
        session_token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        expires_at = now + self.ttl_seconds
        with self._lock:
            self._sessions[self._digest(session_token)] = SessionRecord(
                username=username,
                role=normalized_role,
                expires_at=expires_at,
                csrf_digest=self._digest(csrf_token),
            )
        if self.audit:
            self.audit.log("session.created", actor=username)
        return SessionCredentials(session_token, csrf_token, expires_at)

    def validate(self, session_token: str) -> SessionRecord | None:
        """Return an active session and eagerly remove it if expired."""
        if not isinstance(session_token, str) or not session_token:
            return None
        key = self._digest(session_token)
        with self._lock:
            record = self._sessions.get(key)
            if record is None:
                return None
            if time.monotonic() >= record.expires_at:
                self._sessions.pop(key, None)
                if self.audit:
                    self.audit.log("session.expired", actor=record.username)
                return None
            return record

    def validate_csrf(self, session_token: str, csrf_token: str) -> bool:
        """Bind a CSRF token to a live session using constant-time comparison."""
        record = self.validate(session_token)
        if record is None or not isinstance(csrf_token, str):
            return False
        return secrets.compare_digest(
            record.csrf_digest, self._digest(csrf_token)
        )

    def require_permission(
        self, session_token: str, permission: str
    ) -> SessionRecord:
        """Return the session or raise a generic authorization failure."""
        record = self.validate(session_token)
        if (
            record is None
            or not isinstance(permission, str)
            or permission not in ROLE_PERMISSIONS[record.role]
        ):
            if self.audit:
                self.audit.log(
                    "authorization.denied", details={"scope": permission}
                )
            raise AuthorizationError(
                "Permission scope denied.", {"permission": permission}
            )
        return record

    def invalidate(self, session_token: str) -> None:
        """Revoke a session without retaining its raw token."""
        if isinstance(session_token, str) and session_token:
            with self._lock:
                self._sessions.pop(self._digest(session_token), None)

    def purge_expired(self) -> int:
        """Remove all expired sessions and return the number removed."""
        now = time.monotonic()
        with self._lock:
            expired = [
                token_digest
                for token_digest, record in self._sessions.items()
                if now >= record.expires_at
            ]
            for token_digest in expired:
                self._sessions.pop(token_digest, None)
            return len(expired)


__all__ = [
    "ROLE_PERMISSIONS",
    "Role",
    "SessionCredentials",
    "SessionManager",
    "SessionRecord",
]
