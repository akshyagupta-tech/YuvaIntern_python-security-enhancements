"""Authentication orchestration with account/IP throttles and scoped sessions."""

from __future__ import annotations

import hashlib
from typing import Any

from audit import AuditLogger
from crypto import PasswordHasher
from database import Database
from rate_limiter import TokenBucketRateLimiter
from sanitizer import InputSanitizer
from security_errors import InputValidationError, RateLimitError
from sessions import Role, SessionCredentials, SessionManager


class AuthenticationService:
    """Register and authenticate users without leaking credential state."""

    MIN_PASSWORD_LENGTH = 12

    def __init__(
        self,
        database: Database,
        *,
        hasher: PasswordHasher | None = None,
        limiter: TokenBucketRateLimiter | None = None,
        sessions: SessionManager | None = None,
        audit: AuditLogger | None = None,
    ) -> None:
        self.database = database
        self.hasher = hasher or PasswordHasher()
        self.audit = audit or AuditLogger()
        self.limiter = limiter or TokenBucketRateLimiter()
        self.sessions = sessions or SessionManager(audit=self.audit)
        self.sanitizer = InputSanitizer()
        self._dummy_salt, self._dummy_hash = self.hasher.hash_password(
            "nonexistent-account timing equalizer"
        )

    @staticmethod
    def _fingerprint(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]

    def register_user(
        self,
        username: str,
        password: str,
        role: Role | str = Role.VIEWER,
    ) -> None:
        """Validate and persist a salted credential without logging its value."""
        clean_username = self.sanitizer.validate_username(username)
        if (
            not isinstance(password, str)
            or len(password) < self.MIN_PASSWORD_LENGTH
        ):
            raise InputValidationError(
                "Password does not meet the minimum length requirement.",
                {"field": "password"},
            )
        try:
            normalized_role = role if isinstance(role, Role) else Role(role)
        except ValueError as error:
            raise InputValidationError("Account role is invalid.") from error
        salt, password_hash = self.hasher.hash_password(password)
        self.database.create_user(
            clean_username,
            salt,
            password_hash,
            normalized_role.value,
        )
        self.audit.log(
            "account.registered",
            actor=self._fingerprint(clean_username),
            details={"role": normalized_role.value},
        )

    def _rate_keys(self, username: str, source_ip: str) -> tuple[str, str]:
        source = source_ip if isinstance(source_ip, str) else "unknown"
        return (
            f"user:{username.casefold()}",
            f"ip:{self._fingerprint(source)}",
        )

    def login(
        self,
        username: str,
        password: str,
        source_ip: str = "unknown",
    ) -> SessionCredentials | None:
        """Authenticate with per-user/per-IP throttles and uniform failures."""
        try:
            clean_username = self.sanitizer.validate_username(username)
        except InputValidationError:
            source_key = self._rate_keys("invalid", source_ip)[1]
            self.limiter.record_failure(source_key)
            self.audit.log("authentication.input_rejected")
            return None

        keys = self._rate_keys(clean_username, source_ip)
        if any(not self.limiter.is_allowed(key) for key in keys):
            self.audit.log(
                "authentication.rate_limited",
                actor=self._fingerprint(clean_username),
            )
            return None

        if not isinstance(password, str):
            for key in keys:
                self.limiter.record_failure(key)
            self.audit.log(
                "authentication.failed",
                actor=self._fingerprint(clean_username),
            )
            return None

        user = self.database.get_user(clean_username)
        if user is None:
            self.hasher.verify_password(
                password, self._dummy_salt, self._dummy_hash
            )
            authenticated = False
        else:
            authenticated = self.hasher.verify_password(
                password,
                user.salt,
                user.password_hash,
            )

        if not authenticated or user is None:
            for key in keys:
                self.limiter.record_failure(key)
            self.audit.log(
                "authentication.failed",
                actor=self._fingerprint(clean_username),
                details={
                    "source_fingerprint": self._fingerprint(str(source_ip))
                },
            )
            return None

        for key in keys:
            self.limiter.reset(key)
        credentials = self.sessions.create_session(clean_username, user.role)
        self.audit.log(
            "authentication.succeeded",
            actor=self._fingerprint(clean_username),
            details={"role": user.role},
        )
        return credentials

    def logout(self, session_token: str) -> None:
        """Revoke a session token and record a non-sensitive event."""
        record = self.sessions.validate(session_token)
        self.sessions.invalidate(session_token)
        if record:
            self.audit.log(
                "session.revoked",
                actor=self._fingerprint(record.username),
            )

    def audit_events(self) -> list[dict[str, Any]]:
        """Return redacted, structured audit events for authorized UI display."""
        return self.audit.records()


__all__ = ["AuthenticationService"]
