"""Security gate used by CI to turn scanner output into a pass or fail decision."""

from security_gate.models import ControlResult, ControlStatus, Finding, Severity

__all__ = ["ControlResult", "ControlStatus", "Finding", "Severity"]
