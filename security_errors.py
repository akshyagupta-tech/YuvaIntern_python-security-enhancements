"""Standardized security exceptions and information-safe public responses."""

from __future__ import annotations

from typing import Any, Mapping


class SecurityError(Exception):
    """Base security exception with internal-only structured context."""

    code = "SEC-500"
    public_message = "The request could not be completed securely."

    def __init__(
        self,
        message: str,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.context = dict(context or {})


class InputValidationError(SecurityError, ValueError):
    """Raised when input violates its schema or allow-list."""

    code = "SEC-400"
    public_message = "The submitted input is invalid."


class AuthenticationError(SecurityError):
    """Raised for invalid credentials without disclosing account existence."""

    code = "SEC-401"
    public_message = "Authentication failed."


class AuthorizationError(SecurityError, PermissionError):
    """Raised when the session lacks a requested permission scope."""

    code = "SEC-403"
    public_message = "You are not authorized to perform this action."


class RateLimitError(SecurityError):
    """Raised when authentication is locked or throttled."""

    code = "SEC-429"
    public_message = "Too many requests. Try again later."


class DatabaseOperationError(SecurityError):
    """Raised when a database operation fails without exposing its internals."""

    code = "SEC-503"
    public_message = "A secure data operation could not be completed."


class DuplicateAccountError(InputValidationError):
    """Raised when a username is already registered."""

    public_message = "The account could not be created with those details."


class SessionExpiredError(AuthorizationError):
    """Raised when a session token has expired or was revoked."""

    code = "SEC-440"
    public_message = "Your session has expired. Sign in again."


def public_error(error: Exception) -> dict[str, str]:
    """Map internal exceptions to stable public codes and generic messages."""
    if isinstance(error, SecurityError):
        return {"code": error.code, "message": error.public_message}
    return {
        "code": "SEC-500",
        "message": SecurityError.public_message,
    }


__all__ = [
    "AuthenticationError",
    "AuthorizationError",
    "DatabaseOperationError",
    "DuplicateAccountError",
    "InputValidationError",
    "RateLimitError",
    "SecurityError",
    "SessionExpiredError",
    "public_error",
]
