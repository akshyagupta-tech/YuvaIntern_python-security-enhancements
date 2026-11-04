"""Unicode normalization, markup removal, and strict input allow-lists."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from html.parser import HTMLParser

from security_errors import InputValidationError

_USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_]{3,32}\Z")
_SAFE_TEXT_PATTERN = re.compile(r"[\w\s.,!?@:/()+-]{0,512}\Z", re.UNICODE)
_DOMAIN_LABEL_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)
_CONTROL_PATTERN = re.compile(r"[\x00-\x1f\x7f]")


class _TextOnlyParser(HTMLParser):
    """Collect visible text while dropping active or styled content."""

    _BLOCK_TAGS = {
        "article",
        "div",
        "li",
        "p",
        "section",
        "br",
        "hr",
    }
    _SUPPRESSED_TAGS = {"script", "style", "iframe", "object", "template"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._suppression_depth = 0

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag in self._SUPPRESSED_TAGS:
            self._suppression_depth += 1
        elif tag in self._BLOCK_TAGS and self._suppression_depth == 0:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SUPPRESSED_TAGS and self._suppression_depth:
            self._suppression_depth -= 1
        elif tag in self._BLOCK_TAGS and self._suppression_depth == 0:
            self.parts.append(" ")

    def handle_data(self, data: str) -> None:
        if self._suppression_depth == 0:
            self.parts.append(data)


class InputSanitizer:
    """Normalize and validate user-controlled text against explicit schemas."""

    def __init__(self, max_length: int = 512) -> None:
        if isinstance(max_length, bool) or not isinstance(max_length, int):
            raise InputValidationError(
                "Maximum input length must be an integer."
            )
        if max_length < 1:
            raise InputValidationError(
                "Maximum input length must be positive."
            )
        self.max_length = max_length

    def sanitize_text(
        self,
        value: str,
        allowed_pattern: re.Pattern[str] = _SAFE_TEXT_PATTERN,
        *,
        field: str = "input",
    ) -> str:
        """Normalize Unicode, remove markup/controls, then enforce an allow-list."""
        if not isinstance(value, str):
            raise InputValidationError("Input must be text.", {"field": field})
        normalized = unicodedata.normalize("NFKC", value)
        parser = _TextOnlyParser()
        try:
            parser.feed(normalized)
            parser.close()
        except Exception as error:
            raise InputValidationError(
                "Input markup could not be safely parsed.", {"field": field}
            ) from error
        text = "".join(parser.parts)
        text = _CONTROL_PATTERN.sub(" ", text)
        text = "".join(
            character
            for character in text
            if unicodedata.category(character) not in {"Cf", "Cs", "Co", "Cn"}
        )
        cleaned = " ".join(text.split())
        if len(cleaned) > self.max_length:
            raise InputValidationError(
                "Input exceeds its permitted length.",
                {
                    "field": field,
                    "length": len(cleaned),
                    "limit": self.max_length,
                },
            )
        if not allowed_pattern.fullmatch(cleaned):
            raise InputValidationError(
                "Input contains characters outside its allow-list.",
                {"field": field},
            )
        return cleaned

    def validate_username(self, username: str) -> str:
        """Validate an account identifier using a strict ASCII allow-list."""
        if not isinstance(username, str):
            raise InputValidationError(
                "Username must be text.", {"field": "username"}
            )
        normalized = unicodedata.normalize("NFKC", username)
        if not _USERNAME_PATTERN.fullmatch(normalized):
            raise InputValidationError(
                "Username must be 3-32 ASCII letters, digits, or underscores.",
                {"field": "username"},
            )
        return normalized

    def validate_hostname(self, hostname: str) -> str:
        """Return a canonical IPv4/IPv6 address or valid IDNA domain name."""
        if not isinstance(hostname, str) or len(hostname) > 253:
            raise InputValidationError(
                "Target host is invalid.", {"field": "host"}
            )
        normalized = unicodedata.normalize("NFKC", hostname).strip()
        try:
            return str(ipaddress.ip_address(normalized))
        except ValueError:
            pass
        if normalized.casefold() == "localhost":
            return "localhost"
        try:
            ascii_host = normalized.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise InputValidationError(
                "Target host is invalid.", {"field": "host"}
            ) from error
        labels = ascii_host.rstrip(".").split(".")
        if (
            len(labels) < 2
            or any(
                not _DOMAIN_LABEL_PATTERN.fullmatch(label) for label in labels
            )
            or not labels[-1].isalpha()
            or not 2 <= len(labels[-1]) <= 63
            or len(ascii_host) > 253
        ):
            raise InputValidationError(
                "Target host is not a valid domain or IP address.",
                {"field": "host"},
            )
        return ascii_host.lower().rstrip(".")


__all__ = ["InputSanitizer"]
