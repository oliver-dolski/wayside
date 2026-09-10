"""Severity rubric: a pure function with no state and no I/O (RISK-03).

The criteria in `RUBRIC_CRITERIA` are rendered in the report's methodology
section so they are documented in the product, not only in the code. This
rubric does NOT compute any aggregate score and does NOT assign a numeric
Security Level.
"""

from __future__ import annotations

__all__ = [
    "ALLOWED_SEVERITIES",
    "SEVERITY_TO_RISK",
    "RUBRIC_CRITERIA",
    "RUBRIC_VERSION",
    "severity_to_risk",
]

ALLOWED_SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")

# Severity is the check's own classification; risk is the word the report
# puts next to it. The two axes are kept deliberately distinct in wording -
# mapping "high" onto "high" would make the risk field a tautology and read
# as a rendering fault rather than as a second piece of information.
SEVERITY_TO_RISK: dict[str, str] = {
    "low": "minor",
    "medium": "moderate",
    "high": "serious",
    "critical": "severe",
}

RUBRIC_VERSION = "1.0"

RUBRIC_CRITERIA: dict[str, str] = {
    "low": (
        "An observation with limited security impact and no direct path to "
        "disrupting the operation of the process."
    ),
    "medium": (
        "A departure from good practice which, combined with another "
        "condition, may lead to disrupting the operation of the process."
    ),
    "high": (
        "An operation that by itself allows the state of the process to be "
        "influenced without authentication or authorisation of the sender."
    ),
    "critical": (
        "A condition enabling immediate and direct interference with the "
        "safety of the process, with no further conditions required."
    ),
}


def severity_to_risk(severity: str) -> str:
    """Returns the risk word for a severity. Raises `ValueError` on a
    severity outside `ALLOWED_SEVERITIES`, never returns a default."""
    if severity not in ALLOWED_SEVERITIES:
        raise ValueError(
            f"Unknown finding severity: {severity!r}. Allowed: {ALLOWED_SEVERITIES}."
        )
    return SEVERITY_TO_RISK[severity]
