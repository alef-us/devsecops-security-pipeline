"""Dependency vulnerability scanning control, backed by pip-audit."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Sequence

from security_gate.models import ControlResult, ControlStatus, Finding, Severity
from security_gate.policy import is_blocking_dependency_finding

CONTROL_NAME = "dependencies"

#: pip-audit exit codes. Anything else means pip-audit itself failed to run.
_PIP_AUDIT_EXIT_CLEAN = 0
_PIP_AUDIT_EXIT_VULNERABLE = 1


def parse_report(payload: dict) -> list[Finding]:
    """Convert a pip-audit JSON report into normalised findings.

    pip-audit does not emit a severity rating, so severity and confidence are
    recorded as UNKNOWN rather than being invented. The dependency policy does
    not depend on a severity label.
    """
    findings: list[Finding] = []
    for dependency in payload.get("dependencies", []):
        name = dependency.get("name", "?")
        version = dependency.get("version", "?")
        for vulnerability in dependency.get("vulns", []):
            fix_versions = vulnerability.get("fix_versions") or []
            remediation = f"fixed in {', '.join(fix_versions)}" if fix_versions else "no fix available"
            aliases = ", ".join(vulnerability.get("aliases") or []) or "no aliases"
            findings.append(
                Finding(
                    control=CONTROL_NAME,
                    identifier=str(vulnerability.get("id", "unknown")),
                    severity=Severity.UNKNOWN,
                    confidence=Severity.UNKNOWN,
                    location=f"{name}=={version}",
                    description=f"{remediation} ({aliases})",
                )
            )
    return findings


def evaluate_report(payload: dict) -> ControlResult:
    """Apply the dependency policy to a parsed pip-audit report."""
    if "dependencies" not in payload:
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.UNAVAILABLE,
            detail="pip-audit returned a report without a dependency list.",
        )

    findings = parse_report(payload)
    blocking = [finding for finding in findings if is_blocking_dependency_finding(finding)]
    scanned = len(payload["dependencies"])
    if blocking:
        affected = {finding.location for finding in blocking}
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.FAILED,
            detail=(
                f"{len(blocking)} known vulnerability(ies) in {len(affected)} of "
                f"{scanned} scanned package(s)."
            ),
            findings=findings,
            blocking_findings=blocking,
        )
    return ControlResult(
        name=CONTROL_NAME,
        status=ControlStatus.PASSED,
        detail=f"No known vulnerabilities in {scanned} scanned package(s).",
        findings=findings,
    )


def scan(extra_args: Sequence[str] = ()) -> ControlResult:
    """Audit the installed environment and evaluate the result.

    The installed environment is audited rather than the requirements files,
    because the requirements files list only direct dependencies while the
    resolved environment is what actually runs.
    """
    command = [
        sys.executable,
        "-m",
        "pip_audit",
        "--format",
        "json",
        "--progress-spinner",
        "off",
        *extra_args,
    ]
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
            detail=f"pip-audit could not be executed: {error}",
        )

    if completed.returncode not in (_PIP_AUDIT_EXIT_CLEAN, _PIP_AUDIT_EXIT_VULNERABLE):
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.UNAVAILABLE,
            detail=(
                f"pip-audit exited with unexpected code {completed.returncode}: "
                f"{completed.stderr.strip()[:300]}"
            ),
        )

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.UNAVAILABLE,
            detail=(
                "pip-audit produced no parsable JSON report, which usually means the "
                f"vulnerability service was unreachable: {completed.stderr.strip()[:300]}"
            ),
        )

    result = evaluate_report(payload)
    # pip-audit reports a non-zero exit only when it found vulnerabilities. A
    # non-zero exit with no parsed findings therefore means the audit failed for
    # some other reason and must not be interpreted as a clean scan.
    if completed.returncode == _PIP_AUDIT_EXIT_VULNERABLE and not result.findings:
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.UNAVAILABLE,
            detail=(
                "pip-audit signalled a failure but reported no findings: "
                f"{completed.stderr.strip()[:300]}"
            ),
        )
    return result
