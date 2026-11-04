"""Thread-safe token-bucket throttling with bounded exponential lockouts."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from threading import RLock

from security_errors import InputValidationError


@dataclass
class _Bucket:
    tokens: float
    updated_at: float
    consecutive_failures: int = 0
    locked_until: float = 0.0


class TokenBucketRateLimiter:
    """Track failed login attempts independently by account and source key."""

    def __init__(
        self,
        capacity: int = 5,
        refill_rate_per_second: float = 1 / 60,
        lockout_threshold: int = 5,
        base_lockout_seconds: float = 5.0,
        max_lockout_seconds: float = 300.0,
    ) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in (capacity, lockout_threshold)
        ):
            raise InputValidationError(
                "Rate limit counts must be positive integers."
            )
        durations = (
            refill_rate_per_second,
            base_lockout_seconds,
            max_lockout_seconds,
        )
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            for value in durations
        ) or (
            refill_rate_per_second <= 0
            or base_lockout_seconds <= 0
            or max_lockout_seconds < base_lockout_seconds
        ):
            raise InputValidationError("Rate limiter durations are invalid.")
        self.capacity = capacity
        self.refill_rate_per_second = float(refill_rate_per_second)
        self.lockout_threshold = lockout_threshold
        self.base_lockout_seconds = float(base_lockout_seconds)
        self.max_lockout_seconds = float(max_lockout_seconds)
        self._buckets: dict[str, _Bucket] = {}
        self._lock = RLock()

    def _bucket(self, key: str, now: float) -> _Bucket:
        return self._buckets.setdefault(
            key, _Bucket(float(self.capacity), now)
        )

    def _refill(self, bucket: _Bucket, now: float) -> None:
        elapsed = max(0.0, now - bucket.updated_at)
        bucket.tokens = min(
            float(self.capacity),
            bucket.tokens + elapsed * self.refill_rate_per_second,
        )
        bucket.updated_at = now

    def is_allowed(self, key: str) -> bool:
        """Return whether the key has a token and is outside its lockout."""
        if not isinstance(key, str) or not key:
            raise InputValidationError(
                "Rate limit key must be non-empty text."
            )
        now = time.monotonic()
        with self._lock:
            bucket = self._bucket(key, now)
            self._refill(bucket, now)
            return now >= bucket.locked_until and bucket.tokens >= 1

    def record_failure(self, key: str) -> float:
        """Consume a token and return the current lockout duration, if any."""
        if not isinstance(key, str) or not key:
            raise InputValidationError(
                "Rate limit key must be non-empty text."
            )
        now = time.monotonic()
        with self._lock:
            bucket = self._bucket(key, now)
            self._refill(bucket, now)
            bucket.tokens = max(0.0, bucket.tokens - 1.0)
            bucket.consecutive_failures += 1
            if bucket.consecutive_failures >= self.lockout_threshold:
                exponent = bucket.consecutive_failures - self.lockout_threshold
                lockout = min(
                    self.max_lockout_seconds,
                    self.base_lockout_seconds * (2**exponent),
                )
                bucket.locked_until = max(bucket.locked_until, now + lockout)
                return lockout
            return 0.0

    def retry_after(self, key: str) -> float:
        """Return the remaining lockout delay, clamped to zero."""
        with self._lock:
            bucket = self._buckets.get(key)
            return (
                max(0.0, bucket.locked_until - time.monotonic())
                if bucket
                else 0.0
            )

    def reset(self, key: str) -> None:
        """Reset a key after successful authentication."""
        with self._lock:
            self._buckets.pop(key, None)


__all__ = ["TokenBucketRateLimiter"]
