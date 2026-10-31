"""Shared data structures for security controls.

Scanners disagree about output formats, so each control adapter converts its own
tool output into these structures. The policy layer then reasons about findings
without knowing which tool produced them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Ordered severity scale shared by every control.

    Scanner severity labels are an estimate, not ground truth, so the gate only
    uses them to decide what must be reviewed before a build is allowed through.
    """

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | None) -> "Severity":
        """Map a scanner label onto the shared scale.

        An unrecognised label becomes UNKNOWN rather than being silently
        downgraded to LOW, because an unparsed label means the gate does not
        understand the finding.
        """
        if value is None:
            return cls.UNKNOWN
        normalised = value.strip().upper()
        aliases = {
            "INFO": cls.LOW,
            "INFORMATIONAL": cls.LOW,
            "MODERATE": cls.MEDIUM,
        }
        if normalised in aliases:
            return aliases[normalised]
        try:
            return cls[normalised]
        except KeyError:
            return cls.UNKNOWN

    def __lt__(self, other: "Severity") -> bool:
        return self.value < other.value

    def __le__(self, other: "Severity") -> bool:
        return self.value <= other.value

    def __gt__(self, other: "Severity") -> bool:
        return self.value > other.value

    def __ge__(self, other: "Severity") -> bool:
        return self.value >= other.value


class ControlStatus(Enum):
    """Outcome of a single security control."""

    PASSED = "passed"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class Finding:
    """A single normalised scanner finding."""

    control: str
    identifier: str
    severity: Severity
    confidence: Severity
    location: str
    description: str

    def summary_line(self) -> str:
        return (
            f"{self.control}: {self.identifier} "
            f"[severity={self.severity.name} confidence={self.confidence.name}] "
            f"{self.location} - {self.description}"
        )


@dataclass
class ControlResult:
    """Result of running one control, including why it passed or failed."""

    name: str
    status: ControlStatus
    detail: str
    findings: list[Finding] = field(default_factory=list)
    blocking_findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status is ControlStatus.PASSED
