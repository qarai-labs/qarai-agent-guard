from qarai_agent_guard.core.schemas.detection import (
    LANGUAGE_ALIASES,
    DetectionResult,
    Match,
)
from qarai_agent_guard.core.schemas.events import Severity


def normalize_language(lang: str) -> str:
    """Map a language alias to a canonical language code.

    Args:
        lang (str): Language code or alias (e.g. ``"en"``, ``"ar"``).
            Required.

    Returns:
        str: Canonical language code.

    Raises:
        TypeError: If ``lang`` is not a string.
        ValueError: If the language is unsupported.
    """
    if not isinstance(lang, str):
        msg = f"lang must be str, got {type(lang).__name__}"
        raise TypeError(msg)
    normalized = LANGUAGE_ALIASES.get(lang.lower(), None)
    if normalized is None:
        msg = f"Unsupported language code: {lang!r}"
        raise ValueError(msg)
    return normalized


def parse_severity(value: str) -> Severity:
    """Parse a severity label into a Severity enum member.

    Args:
        value (str): Severity label. Required.

    Returns:
        Severity: Parsed enum member.

    Raises:
        TypeError: If ``value`` is not a string.
        ValueError: If the label is not a valid severity.
    """
    if not isinstance(value, str):
        msg = f"value must be str, got {type(value).__name__}"
        raise TypeError(msg)
    try:
        return Severity(value.lower())
    except ValueError as exc:
        msg = f"Invalid severity value: {value!r}"
        raise ValueError(msg) from exc


def highest_match_severity(matches: list[Match]) -> Severity | None:
    """Return the highest severity among a list of pattern matches.

    Args:
        matches (list[Match]): Match objects to compare. Required.

    Returns:
        Severity | None: Highest severity, or ``None`` when ``matches`` is
        empty.
    """
    if not matches:
        return None
    return max(
        (parse_severity(match.severity) for match in matches),
        key=lambda severity: list(Severity).index(severity),
    )


def highest_result_severity(result: DetectionResult) -> Severity | None:
    """Return the highest severity found in one detection result.

    Args:
        result (DetectionResult): Detection result to inspect. Required.

    Returns:
        Severity | None: Highest match severity, or ``None`` when no matches
        exist.
    """
    match_severity = highest_match_severity(result.matches)
    if result.model_detection_result is None:
        return match_severity

    metadata = getattr(result.model_detection_result, "metadata", {}) or {}
    # ``severity`` is the normalized model-output contract.  The metadata
    # fallback preserves compatibility with detection results created by 0.x.
    model_severity = getattr(
        result.model_detection_result, "severity", None
    ) or metadata.get("max_severity")
    if isinstance(model_severity, Severity):
        candidate_severities = [model_severity]
    elif isinstance(model_severity, str):
        try:
            candidate_severities = [parse_severity(model_severity)]
        except ValueError:
            candidate_severities = []
    else:
        candidate_severities = []

    if match_severity is not None:
        candidate_severities.append(match_severity)

    if not candidate_severities:
        return None

    return max(
        candidate_severities,
        key=lambda severity: list(Severity).index(severity),
    )


def highest_results_severity(
    results: list[DetectionResult],
) -> Severity | None:
    """Return the highest severity across multiple detection results.

    Args:
        results (list[DetectionResult]): Detection results to compare.
            Required.

    Returns:
        Severity | None: Highest severity, or ``None`` when no matches exist.
    """

    severities = [
        severity
        for result in results
        if (severity := highest_result_severity(result)) is not None
    ]

    if not severities:
        return None
    return max(
        severities,
        key=lambda severity: list(Severity).index(severity),
    )
