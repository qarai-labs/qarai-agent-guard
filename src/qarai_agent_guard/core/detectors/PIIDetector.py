from __future__ import annotations

from pathlib import Path
from typing import Any

from qarai_agent_guard.core.detectors.BaseDetector import BaseDetector
from qarai_agent_guard.core.helpers.stringify import _stringify
from qarai_agent_guard.core.loaders.pattern_loader import PatternLoader
from qarai_agent_guard.core.schemas.detection import PATTERNS_ROOT, DetectionResult, Match


class PIIDetector(BaseDetector):
    """Detect personally identifiable information patterns.

    This detector loads common PII detection rules and scans payloads for
    sensitive information patterns. Specific rules can be excluded using
    the ``ignore`` option before regex compilation.

    Attributes:
        name: Unique detector identifier.
        default_message: Message returned when PII is detected.
    """

    name = "pii"
    default_message = "Personally identifiable information detected"

    def __init__(
        self,
        *,
        patterns: list[dict[str, Any]] | None = None,
        pattern_paths: list[Path] | None = None,
        ignore: frozenset[str] | None = None,
        loader: PatternLoader | None = None,
    ) -> None:
        """Initialize the PII detector.

        Args:
            patterns: Optional inline PII rules. When provided, these replace
                the default rules loaded from the pattern repository.
            ignore: Optional set of rule identifiers to exclude after loading
                the pattern definitions.
            loader: Optional pattern loader instance. If omitted, a loader
                using the built-in pattern directory is created.

        Raises:
            TypeError:
                If ``ignore`` is not a ``frozenset`` or ``loader`` is not a
                ``PatternLoader`` instance.
        """
        if ignore is not None and not isinstance(ignore, frozenset):
            msg = f"ignore must be frozenset or None, got {type(ignore).__name__}"
            raise TypeError(msg)

        if loader is not None and not isinstance(loader, PatternLoader):
            msg = f"loader must be PatternLoader or None, got {type(loader).__name__}"
            raise TypeError(msg)

        self._ignore = ignore or frozenset()

        super().__init__(
            lang="common",
            patterns=patterns,
            pattern_paths=pattern_paths,
            loader=loader or PatternLoader(PATTERNS_ROOT),
        )

        if self._ignore:
            self._rules = [
                rule for rule in self._rules if rule["id"] not in self._ignore
            ]

            self._rules, self._compiled = self._compile_pattern_rules(
                self._rules,
            )

    def _load_default_rules(self) -> list[dict[str, Any]]:
        """Load default PII detection rules.

        Loads the built-in PII pattern definitions from the common pattern
        directory.

        Returns:
            A list of PII rule definitions used by the detector.

        Raises:
            FileNotFoundError:
                If the default PII pattern file cannot be found.
        """
        return self._loader.load_patterns(
            PATTERNS_ROOT / "common" / "pii.yaml",
        )

    @staticmethod
    def _is_luhn_valid(candidate: str) -> bool:
        """Return whether a candidate card number passes Luhn checksum."""
        digits = "".join(ch for ch in candidate if ch.isdigit())
        if len(digits) < 13 or len(digits) > 19:
            return False

        total = 0
        parity = len(digits) % 2
        for index, char in enumerate(digits):
            digit = int(char)
            if index % 2 == parity:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit
        return total % 10 == 0

    def inspect(
        self,
        key: str,
        value: Any,
        *,
        operation: str,
    ) -> DetectionResult:
        """Scan payload and apply Luhn filtering to credit card candidates."""
        if not isinstance(key, str):
            msg = f"key must be str, got {type(key).__name__}"
            raise TypeError(msg)
        if not key.strip():
            msg = "key must not be empty"
            raise ValueError(msg)
        if not isinstance(operation, str):
            msg = f"operation must be str, got {type(operation).__name__}"
            raise TypeError(msg)
        if not operation.strip():
            msg = "operation must not be empty"
            raise ValueError(msg)

        text = _stringify(value)
        if not text:
            return DetectionResult(detector=self.name, matched=False)

        hits: list[Match] = []
        for index, pattern in enumerate(self._compiled):
            rule = self._rules[index]

            if rule["id"] == "credit_card":
                candidate = next(
                    (
                        match.group(0)
                        for match in pattern.finditer(text)
                        if self._is_luhn_valid(match.group(0))
                    ),
                    None,
                )
                if candidate is None:
                    continue
                hit = candidate
            else:
                match = pattern.search(text)
                if not match:
                    continue
                hit = match.group(0)

            hits.append(
                Match(
                    pattern_id=rule["id"],
                    pattern_name=rule["name"],
                    severity=rule["severity"],
                    match=hit,
                )
            )

        if not hits:
            return DetectionResult(detector=self.name, matched=False)

        return DetectionResult(
            detector=self.name,
            matched=True,
            matches=hits,
            message=f"{self.default_message} in '{key}'",
            metadata={
                "language": self._lang,
                "hit_count": len(hits),
                "operation": operation,
            },
        )

    def redact(self, value: Any) -> Any:
        """Redact only Luhn-valid credit cards; keep invalid numeric strings."""
        credit_card_redaction = "[REDACTED:credit_card]"
        original = _stringify(value)
        for index, pattern in enumerate(self._compiled):
            rule = self._rules[index]
            if rule["id"] == "credit_card":
                original = pattern.sub(
                    lambda m: (
                        credit_card_redaction
                        if self._is_luhn_valid(m.group(0))
                        else m.group(0)
                    ),
                    original,
                )
            else:
                original = pattern.sub(f"[REDACTED:{rule['id']}]", original)
        return original
