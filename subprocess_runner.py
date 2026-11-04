"""Strictly validated, timeout-bounded subprocess helpers."""

from __future__ import annotations

import math
import subprocess

from sanitizer import InputSanitizer
from security_errors import SecurityError

_SANITIZER = InputSanitizer()


def safe_network_ping(hostname: str, timeout_seconds: float = 3.0) -> bool:
    """Probe a validated host through argv without invoking a command shell."""
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > 10
    ):
        raise ValueError(
            "Network probe timeout must be between 0 and 10 seconds."
        )
    target = _SANITIZER.validate_hostname(hostname)
    try:
        result = subprocess.run(
            ["ping", "-c", "1", target],
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=float(timeout_seconds),
        )
    except subprocess.TimeoutExpired as error:
        raise SecurityError(
            "Network diagnostic timed out.", {"operation": "network_probe"}
        ) from error
    except OSError as error:
        raise SecurityError(
            "Network diagnostic could not be completed.",
            {"operation": "network_probe", "error_type": type(error).__name__},
        ) from error
    return result.returncode == 0


__all__ = ["safe_network_ping"]
