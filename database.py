"""SQLite DB-API repository using static SQL and bound parameters only."""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from security_errors import (
    DatabaseOperationError,
    DuplicateAccountError,
    InputValidationError,
)

_USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_]{3,32}\Z")
_ROLES = {"Viewer", "Operator", "Administrator"}


@dataclass(frozen=True)
class UserRecord:
    """Read-only credential and role record returned by the repository."""

    username: str
    salt: str
    password_hash: str
    role: str


class Database:
    """Own SQLite connections and expose only parameterized user operations."""

    def __init__(self, path: str | Path, timeout_seconds: float = 5.0) -> None:
        requested_path = str(path)
        self._uri = requested_path == ":memory:"
        self.path = (
            f"file:week5-{secrets.token_hex(8)}?mode=memory&cache=shared"
            if self._uri
            else requested_path
        )
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise InputValidationError("Database timeout must be positive.")
        self.timeout_seconds = float(timeout_seconds)
        self._keeper = (
            sqlite3.connect(self.path, uri=True, check_same_thread=False)
            if self._uri
            else None
        )

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout_seconds,
            uri=self._uri,
        )
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        """Create the account schema without deleting or seeding user data."""
        if not self._uri:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._connection() as connection:
                connection.execute("""CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY NOT NULL,
                        salt TEXT NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )""")
            if not self._uri and Path(self.path).exists():
                os.chmod(self.path, 0o600)
        except sqlite3.Error as error:
            raise DatabaseOperationError(
                "Database initialization failed.",
                {
                    "operation": "initialize",
                    "error_type": type(error).__name__,
                },
            ) from error

    def create_user(
        self,
        username: str,
        salt: str,
        password_hash: str,
        role: str,
    ) -> None:
        """Create one account using DB-API tuple binding."""
        if not isinstance(username, str) or not _USERNAME_PATTERN.fullmatch(
            username
        ):
            raise InputValidationError(
                "Username is invalid.", {"field": "username"}
            )
        if not isinstance(role, str) or role not in _ROLES:
            raise InputValidationError("Role is invalid.", {"field": "role"})
        if not all(
            isinstance(value, str) and value for value in (salt, password_hash)
        ):
            raise InputValidationError("Credential fields are invalid.")
        try:
            with self._connection() as connection:
                connection.execute(
                    "INSERT INTO users (username, salt, password_hash, role) "
                    "VALUES (?, ?, ?, ?)",
                    (username, salt, password_hash, role),
                )
        except sqlite3.IntegrityError as error:
            raise DuplicateAccountError(
                "Account already exists.", {"operation": "create_user"}
            ) from error
        except sqlite3.Error as error:
            raise DatabaseOperationError(
                "Account creation failed.",
                {
                    "operation": "create_user",
                    "error_type": type(error).__name__,
                },
            ) from error

    def get_user(self, username: str) -> UserRecord | None:
        """Fetch one account by exact username with a single bound parameter."""
        if not isinstance(username, str) or len(username) > 128:
            return None
        try:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT username, salt, password_hash, role FROM users "
                    "WHERE username = ?",
                    (username,),
                ).fetchone()
        except sqlite3.Error as error:
            raise DatabaseOperationError(
                "Account lookup failed.",
                {"operation": "get_user", "error_type": type(error).__name__},
            ) from error
        if row is None:
            return None
        return UserRecord(*row)

    def user_count(self) -> int:
        """Return the number of registered users without exposing row contents."""
        try:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT COUNT(*) FROM users"
                ).fetchone()
        except sqlite3.Error as error:
            raise DatabaseOperationError(
                "Account count failed.",
                {
                    "operation": "user_count",
                    "error_type": type(error).__name__,
                },
            ) from error
        return int(row[0]) if row else 0

    def close(self) -> None:
        """Release the keeper connection used by a shared in-memory database."""
        if self._keeper is not None:
            self._keeper.close()
            self._keeper = None


__all__ = ["Database", "UserRecord"]
