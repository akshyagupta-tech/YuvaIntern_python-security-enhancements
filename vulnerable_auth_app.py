"""Non-executing descriptions of insecure patterns for defensive comparison."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class SecurityComparison:
    """Describe a vulnerable design and its hardened architectural control."""

    area: str
    vulnerable_design: str
    defensive_control: str


COMPARISONS = (
    SecurityComparison(
        area="Database access",
        vulnerable_design="Build query text from untrusted input; this demo does not execute it.",
        defensive_control="Use fixed SQL statements and bind values through DB-API parameters.",
    ),
    SecurityComparison(
        area="Process execution",
        vulnerable_design="Pass user-controlled command text to a shell; this demo never runs it.",
        defensive_control="Validate a host and pass a fixed argv list with shell disabled and a timeout.",
    ),
    SecurityComparison(
        area="Credential storage",
        vulnerable_design="Store a password directly; the application does not create such records.",
        defensive_control="Store a per-user PBKDF2-HMAC-SHA256 digest and random salt.",
    ),
)


def comparison_examples() -> list[dict[str, str]]:
    """Return inert comparison data for the security diagnostics UI."""
    return [asdict(example) for example in COMPARISONS]


__all__ = ["COMPARISONS", "SecurityComparison", "comparison_examples"]
