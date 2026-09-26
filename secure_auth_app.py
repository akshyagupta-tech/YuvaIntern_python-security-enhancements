"""
Enterprise Hardened Authentication & Security Engine (Week 5)
Author: Akshya Gupta (YuvaIntern Junior Python Developer Track)
Defenses: Parameterized SQL, PBKDF2 Hashing, Rate Limiting, Session Tokens, Whitelisting
"""

from __future__ import annotations
import sqlite3
import hashlib
import secrets
import subprocess
import re
import time
import logging
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SECURITY_AUDIT] [%(levelname)s] %(message)s"
)
logger = logging.getLogger("EnterpriseSecurityEngine")

DB_FILE = "secure_users.db"

class SecurityValidationError(ValueError):
    """Untrusted payload validation failure."""

@dataclass
class SessionRecord:
    username: str
    role: str
    expires_at: float

class EnterpriseSecurityEngine:
    # In-memory rate limiting: {username: [timestamps]}
    _failed_attempts: Dict[str, list[float]] = {}
    _active_sessions: Dict[str, SessionRecord] = {}
    
    MAX_ATTEMPTS: int = 5
    LOCKOUT_WINDOW_SECONDS: int = 60
    SESSION_TTL_SECONDS: int = 1800  # 30 minutes

    @staticmethod
    def hash_password(password: str) -> Tuple[str, str]:
        """PBKDF2-HMAC-SHA256 with 100,000 rounds and 16-byte random salt."""
        salt = secrets.token_hex(16)
        key = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=password.encode("utf-8"),
            salt=salt.encode("utf-8"),
            iterations=100_000
        )
        return salt, key.hex()

    @staticmethod
    def verify_password(password: str, salt: str, stored_hash: str) -> bool:
        """Constant-time hash comparison resisting timing analysis attacks."""
        calculated = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=password.encode("utf-8"),
            salt=salt.encode("utf-8"),
            iterations=100_000
        ).hex()
        return secrets.compare_digest(calculated, stored_hash)

    @classmethod
    def _is_rate_limited(cls, identifier: str) -> bool:
        now = time.time()
        cls._failed_attempts[identifier] = [
            t for t in cls._failed_attempts.get(identifier, [])
            if now - t < cls.LOCKOUT_WINDOW_SECONDS
        ]
        return len(cls._failed_attempts[identifier]) >= cls.MAX_ATTEMPTS

    @classmethod
    def _register_failure(cls, identifier: str) -> None:
        if identifier not in cls._failed_attempts:
            cls._failed_attempts[identifier] = []
        cls._failed_attempts[identifier].append(time.time())
        logger.warning("Authentication failure logged for entity: %s (Total in window: %d)",
                       identifier, len(cls._failed_attempts[identifier]))

    @classmethod
    def _clear_failures(cls, identifier: str) -> None:
        cls._failed_attempts.pop(identifier, None)

    @classmethod
    def init_hardened_db(cls) -> None:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL
                )
            """)
            c.execute("DELETE FROM users")
            
            admin_salt, admin_hash = cls.hash_password("SuperSecretAdminPass123")
            alice_salt, alice_hash = cls.hash_password("alicepassword")
            
            c.execute("INSERT INTO users (username, salt, password_hash, role) VALUES (?, ?, ?, ?)",
                      ("admin", admin_salt, admin_hash, "admin"))
            c.execute("INSERT INTO users (username, salt, password_hash, role) VALUES (?, ?, ?, ?)",
                      ("alice", alice_salt, alice_hash, "user"))
            conn.commit()

    @classmethod
    def authenticate_and_create_session(cls, username: str, password: str) -> Optional[str]:
        """Parameterized auth flow with rate-limiting and secure session creation."""
        # Input boundary validation
        if not (isinstance(username, str) and re.match(r"^[a-zA-Z0-9_]{3,30}$", username)):
            logger.warning("Audit Alert: Invalid username format rejected: %r", username)
            return None

        if cls._is_rate_limited(username):
            logger.error("Audit Alert: Account locked due to rate limit threshold: %s", username)
            return None

        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT salt, password_hash, role FROM users WHERE username = ?", (username,))
            record = c.fetchone()
            
            if not record:
                cls._register_failure(username)
                return None

            salt, stored_hash, role = record
            if cls.verify_password(password, salt, stored_hash):
                cls._clear_failures(username)
                token = secrets.token_urlsafe(32)
                cls._active_sessions[token] = SessionRecord(
                    username=username,
                    role=role,
                    expires_at=time.time() + cls.SESSION_TTL_SECONDS
                )
                logger.info("Audit Event: Successful authentication for %s (Role: %s)", username, role)
                return token
            else:
                cls._register_failure(username)
                return None

    @classmethod
    def authenticate_user(cls, username: str, password: str) -> Optional[str]:
        """Backward-compatible role verification interface."""
        token = cls.authenticate_and_create_session(username, password)
        if token and token in cls._active_sessions:
            return cls._active_sessions[token].role
        return None

    @classmethod
    def validate_session(cls, token: str) -> Optional[SessionRecord]:
        session = cls._active_sessions.get(token)
        if not session:
            return None
        if time.time() > session.expires_at:
            cls._active_sessions.pop(token, None)
            return None
        return session

    @staticmethod
    def safe_network_ping(hostname: str) -> bool:
        """Command injection mitigation via regex whitelisting and direct argument vectors."""
        domain_regex = r"^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$"
        ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"

        if not (re.match(domain_regex, hostname) or re.match(ip_regex, hostname) or hostname == "localhost"):
            raise SecurityValidationError(f"Invalid target address for network probe: {hostname!r}")

        cmd = ["ping", "-c", "1", hostname]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False)
        return proc.returncode == 0
