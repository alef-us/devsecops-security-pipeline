"""Static application security testing control, backed by Bandit."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Sequence

from security_gate.models import ControlResult, ControlStatus, Finding, Severity
from security_gate.policy import is_blocking_sast_finding

CONTROL_NAME = "sast"

#: Production code scanned by the gate. Targets are listed explicitly rather than
#: scanning the repository root, so that adding a test fixture can never silently
#: widen or narrow the production scan surface.
DEFAULT_TARGETS: tuple[str, ...] = ("app.py", "security_gate")

#: Bandit exit codes. Anything else means Bandit itself failed to run correctly.
_BANDIT_EXIT_CLEAN = 0
_BANDIT_EXIT_FINDINGS = 1


def parse_report(payload: dict) -> list[Finding]:
    """Convert a Bandit JSON report into normalised findings."""
    findings: list[Finding] = []
    for result in payload.get("results", []):
        location = f"{result.get('filename', '?')}:{result.get('line_number', '?')}"
        findings.append(
            Finding(
                control=CONTROL_NAME,
                identifier=str(result.get("test_id", "unknown")),
                severity=Severity.parse(result.get("issue_severity")),
                confidence=Severity.parse(result.get("issue_confidence")),
                location=location,
                description=str(result.get("issue_text", "")).strip(),
            )
        )
    return findings


def evaluate_report(payload: dict) -> ControlResult:
    """Apply the security policy to a parsed Bandit report.

    Bandit records files it could not analyse in ``errors``. Those are treated as
    an unavailable control, because an unscanned file has not been proven clean.
    """
    scan_errors = payload.get("errors") or []
    if scan_errors:
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.UNAVAILABLE,
            detail=f"Bandit reported {len(scan_errors)} scan error(s); results are incomplete.",
        )

    findings = parse_report(payload)
    blocking = [finding for finding in findings if is_blocking_sast_finding(finding)]
    if blocking:
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.FAILED,
            detail=f"{len(blocking)} finding(s) violate the static analysis policy.",
            findings=findings,
            blocking_findings=blocking,
        )
    return ControlResult(
        name=CONTROL_NAME,
        status=ControlStatus.PASSED,
        detail=(
            f"No blocking findings. {len(findings)} finding(s) below the policy "
            "threshold require manual triage only."
        ),
        findings=findings,
    )


def scan(targets: Sequence[str] = DEFAULT_TARGETS) -> ControlResult:
    """Run Bandit over the given targets and evaluate the result."""
    command = [sys.executable, "-m", "bandit", "--format", "json", "--recursive", *targets]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed command, no shell, no user input
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.UNAVAILABLE,
            detail=f"Bandit could not be executed: {error}",
        )

    if completed.returncode not in (_BANDIT_EXIT_CLEAN, _BANDIT_EXIT_FINDINGS):
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.UNAVAILABLE,
            detail=(
                f"Bandit exited with unexpected code {completed.returncode}: "
                f"{completed.stderr.strip()[:300]}"
            ),
        )

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.UNAVAILABLE,
            detail=f"Bandit produced output that could not be parsed as JSON: {error}",
        )

    return evaluate_report(payload)
