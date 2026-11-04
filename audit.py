"""Structured tamper-evident audit logging with recursive sensitive-data redaction."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Mapping, Sequence

_SENSITIVE_KEY_PATTERN = re.compile(
    r"password|passphrase|secret|token|api[_-]?key|authorization|credential|"
    r"csrf|private[_-]?key|ip[_-]?address",
    re.IGNORECASE,
)
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(password|passphrase|secret|api[_-]?key|access[_-]?token|"
    r"csrf[_-]?token)\b(\s*[=:]\s*)([^\s,;]+)"
)
_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
_PHONE_PATTERN = re.compile(r"(?<!\w)\+?\d[\d ()-]{7,}\d(?!\w)")
_EVENT_PATTERN = re.compile(r"[a-zA-Z0-9_.-]{1,64}\Z")


def redact_value(value: Any, key: str | None = None) -> Any:
    """Return a JSON-safe, recursively redacted copy of structured data."""
    if key is not None and _SENSITIVE_KEY_PATTERN.search(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {
            str(child_key): redact_value(child_value, str(child_key))
            for child_key, child_value in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        cleaned = _ASSIGNMENT_PATTERN.sub(r"\1\2[REDACTED]", value)
        cleaned = _BEARER_PATTERN.sub("Bearer [REDACTED]", cleaned)
        cleaned = _EMAIL_PATTERN.sub("[REDACTED_EMAIL]", cleaned)
        return _PHONE_PATTERN.sub("[REDACTED_PHONE]", cleaned)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return f"<{type(value).__name__}>"


class AuditLogger:
    """Append redacted JSON records linked by an HMAC integrity chain."""

    def __init__(self, hmac_key: bytes | None = None) -> None:
        if hmac_key is not None and (
            not isinstance(hmac_key, bytes) or len(hmac_key) < 32
        ):
            raise ValueError("Audit HMAC key must contain at least 32 bytes.")
        self._key = hmac_key or secrets.token_bytes(32)
        self._records: list[dict[str, Any]] = []
        self._lock = RLock()

    @staticmethod
    def _canonical(record: Mapping[str, Any]) -> bytes:
        return json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def log(
        self,
        event: str,
        *,
        actor: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record one event with secrets, credentials, PII, and tokens redacted."""
        normalized_event = (
            event
            if isinstance(event, str) and _EVENT_PATTERN.fullmatch(event)
            else "security.event"
        )
        with self._lock:
            previous_hash = (
                self._records[-1]["integrity"] if self._records else "0" * 64
            )
            record: dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sequence": len(self._records) + 1,
                "event": normalized_event,
                "actor": redact_value(actor, "actor"),
                "details": redact_value(details or {}),
                "previous_integrity": previous_hash,
            }
            record["integrity"] = hmac.new(
                self._key,
                self._canonical(record),
                hashlib.sha256,
            ).hexdigest()
            self._records.append(record)
            return deepcopy(record)

    def records(self) -> list[dict[str, Any]]:
        """Return an isolated copy of the in-memory redacted audit trail."""
        with self._lock:
            return deepcopy(self._records)

    def verify_chain(
        self,
        records: Sequence[Mapping[str, Any]] | None = None,
    ) -> bool:
        """Verify sequential links and HMACs without exposing key material."""
        chain = self.records() if records is None else list(records)
        previous_hash = "0" * 64
        for expected_sequence, source_record in enumerate(chain, start=1):
            record = dict(source_record)
            supplied_hash = record.pop("integrity", None)
            if (
                record.get("sequence") != expected_sequence
                or record.get("previous_integrity") != previous_hash
                or not isinstance(supplied_hash, str)
            ):
                return False
            expected_hash = hmac.new(
                self._key,
                self._canonical(record),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected_hash, supplied_hash):
                return False
            previous_hash = supplied_hash
        return True

    def write_jsonl(self, path: str | Path) -> None:
        """Write redacted records to a file created with owner-only permissions."""
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        descriptor = os.open(destination, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                for record in self.records():
                    output.write(json.dumps(record, sort_keys=True) + "\n")
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise


__all__ = ["AuditLogger", "redact_value"]
