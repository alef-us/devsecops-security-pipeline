"""Secret detection control, backed by Gitleaks.

Gitleaks is always invoked with ``--redact`` so that a detected secret value is
never written to a log, a report, or the gate summary. The gate reports where a
secret is and which rule matched, never the secret itself.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path

from security_gate.models import ControlResult, ControlStatus, Finding, Severity
from security_gate.policy import is_blocking_secret_finding

CONTROL_NAME = "secrets"

#: Local development fallback. CI installs a checksum-verified binary onto PATH.
_LOCAL_TOOL_DIR = Path(__file__).resolve().parent.parent / ".tools"


def find_executable() -> str | None:
    """Locate the Gitleaks binary, preferring an explicitly configured path."""
    configured = os.environ.get("GITLEAKS_PATH")
    if configured and Path(configured).is_file():
        return configured
    discovered = shutil.which("gitleaks")
    if discovered:
        return discovered
    for candidate in (_LOCAL_TOOL_DIR / "gitleaks.exe", _LOCAL_TOOL_DIR / "gitleaks"):
        if candidate.is_file():
            return str(candidate)
    return None


def parse_report(payload: list) -> list[Finding]:
    """Convert a Gitleaks JSON report into normalised findings.

    The ``Secret`` field is deliberately never read. With ``--redact`` it holds
    a placeholder, and reading it at all would risk printing a real credential
    if the flag were ever dropped.
    """
    findings: list[Finding] = []
    for leak in payload:
        location = f"{leak.get('File', '?')}:{leak.get('StartLine', '?')}"
        commit = str(leak.get("Commit") or "").strip()
        if commit:
            location = f"{location} (commit {commit[:12]})"
        findings.append(
            Finding(
                control=CONTROL_NAME,
                identifier=str(leak.get("RuleID", "unknown")),
                severity=Severity.HIGH,
                confidence=Severity.HIGH,
                location=location,
                description=str(leak.get("Description", "")).strip() or "potential secret",
            )
        )
    return findings


def evaluate_report(payload: list) -> ControlResult:
    """Apply the secret policy to a parsed Gitleaks report."""
    findings = parse_report(payload)
    blocking = [finding for finding in findings if is_blocking_secret_finding(finding)]
    if blocking:
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.FAILED,
            detail=(
                f"{len(blocking)} potential secret(s) detected. Values are redacted; "
                "rotate the credential first, then remove it from history."
            ),
            findings=findings,
            blocking_findings=blocking,
        )
    return ControlResult(
        name=CONTROL_NAME,
        status=ControlStatus.PASSED,
        detail="No secrets detected.",
    )


def _run(mode: str, target: str, extra_args: Sequence[str]) -> ControlResult:
    executable = find_executable()
    if executable is None:
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.UNAVAILABLE,
            detail="Gitleaks is not installed; set GITLEAKS_PATH or add it to PATH.",
        )

    with tempfile.TemporaryDirectory() as workspace:
        report_path = Path(workspace) / "gitleaks-report.json"
        command = [
            executable,
            mode,
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--redact",
            "--no-banner",
            *extra_args,
            target,
        ]
        try:
            completed = subprocess.run(  # noqa: S603 - fixed command, no shell
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as error:
            return ControlResult(
                name=CONTROL_NAME,
                status=ControlStatus.UNAVAILABLE,
                detail=f"Gitleaks could not be executed: {error}",
            )

        # Gitleaks uses exit code 1 both for "secrets found" and for a fatal
        # error, so the exit code alone cannot be trusted. A fatal error writes
        # no report, which is what actually distinguishes the two cases.
        if not report_path.is_file():
            return ControlResult(
                name=CONTROL_NAME,
                status=ControlStatus.UNAVAILABLE,
                detail=f"Gitleaks wrote no report: {completed.stderr.strip()[:300]}",
            )
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8") or "[]")
        except json.JSONDecodeError as error:
            return ControlResult(
                name=CONTROL_NAME,
                status=ControlStatus.UNAVAILABLE,
                detail=f"Gitleaks report could not be parsed: {error}",
            )

    if completed.returncode not in (0, 1):
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.UNAVAILABLE,
            detail=(
                f"Gitleaks exited with unexpected code {completed.returncode}: "
                f"{completed.stderr.strip()[:300]}"
            ),
        )
    return evaluate_report(payload)


def scan_directory(target: str) -> ControlResult:
    """Scan files on disk, ignoring Git history."""
    return _run("dir", target, ())


def scan(target: str = ".") -> ControlResult:
    """Scan the repository including its commit history.

    History matters: removing a secret from the latest commit does not remove it
    from earlier commits, and a shallow clone would hide exactly that case.
    """
    return _run("git", target, ())
