"""GitHub Actions workflow auditing control, backed by zizmor.

This replaces an earlier step that asserted the workflow file contained the
strings ``permissions:`` and ``contents: read``. That check could not fail in
any useful way: it passed as long as the text appeared anywhere in the file,
including inside a comment.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from security_gate.models import ControlResult, ControlStatus, Finding, Severity
from security_gate.policy import is_blocking_workflow_finding

CONTROL_NAME = "workflows"

#: zizmor maps finding severity onto distinct exit codes, which makes "a finding
#: was reported" indistinguishable from "the tool failed". ``--no-exit-codes``
#: removes that ambiguity: zizmor then exits 0 whenever it ran successfully, so
#: a non-zero exit means a genuine tool failure and the gate decides policy from
#: the JSON report alone.
_ZIZMOR_EXIT_OK = 0

DEFAULT_TARGET = ".github"


def find_executable() -> str | None:
    """Locate the zizmor binary.

    zizmor is distributed as a compiled executable rather than an importable
    module, so ``python -m zizmor`` does not work. The directory holding the
    current interpreter is searched first so that a virtual environment is
    preferred over any unrelated copy on PATH.
    """
    configured = os.environ.get("ZIZMOR_PATH")
    if configured and Path(configured).is_file():
        return configured
    interpreter_dir = Path(sys.executable).parent
    for candidate in (interpreter_dir / "zizmor.exe", interpreter_dir / "zizmor"):
        if candidate.is_file():
            return str(candidate)
    return shutil.which("zizmor")


def _location(finding: dict) -> str:
    locations = finding.get("locations") or []
    if not locations:
        return "unknown"
    symbolic = locations[0].get("symbolic", {})
    key = symbolic.get("key", {}).get("Local", {})
    path = str(key.get("verbatim_path", "unknown")).replace("\\", "/")
    row = locations[0].get("concrete", {}).get("location", {}).get("start_point", {}).get("row")
    # zizmor reports zero-based rows; editors and reviewers count from one.
    line = row + 1 if isinstance(row, int) else "?"
    annotation = str(symbolic.get("annotation", "")).strip()
    return f"{path}:{line}" + (f" ({annotation})" if annotation else "")


def parse_report(payload: list) -> list[Finding]:
    """Convert a zizmor JSON report into normalised findings."""
    findings: list[Finding] = []
    for entry in payload:
        determinations = entry.get("determinations", {})
        description = str(entry.get("desc", "")).strip() or "workflow issue"
        url = str(entry.get("url", "")).strip()
        findings.append(
            Finding(
                control=CONTROL_NAME,
                identifier=str(entry.get("ident", "unknown")),
                severity=Severity.parse(determinations.get("severity")),
                confidence=Severity.parse(determinations.get("confidence")),
                location=_location(entry),
                description=f"{description} ({url})" if url else description,
            )
        )
    return findings


def evaluate_report(payload: list) -> ControlResult:
    """Apply the workflow policy to a parsed zizmor report."""
    findings = parse_report(payload)
    blocking = [finding for finding in findings if is_blocking_workflow_finding(finding)]
    if blocking:
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.FAILED,
            detail=f"{len(blocking)} workflow finding(s) violate the policy.",
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


def scan(targets: Sequence[str] = (DEFAULT_TARGET,)) -> ControlResult:
    """Audit the workflow definitions and evaluate the result.

    ``--offline`` is used so the audit needs no network access and no token.
    Audits that require the GitHub API are therefore skipped; see the README.
    """
    executable = find_executable()
    if executable is None:
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.UNAVAILABLE,
            detail="zizmor is not installed; set ZIZMOR_PATH or add it to PATH.",
        )
    command = [
        executable,
        "--format",
        "json",
        "--no-progress",
        "--no-exit-codes",
        "--offline",
        *targets,
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
            detail=f"zizmor could not be executed: {error}",
        )

    if completed.returncode != _ZIZMOR_EXIT_OK:
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.UNAVAILABLE,
            detail=(
                f"zizmor failed with exit code {completed.returncode}: "
                f"{completed.stderr.strip()[:300]}"
            ),
        )

    try:
        payload = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as error:
        return ControlResult(
            name=CONTROL_NAME,
            status=ControlStatus.UNAVAILABLE,
            detail=f"zizmor produced output that could not be parsed as JSON: {error}",
        )

    return evaluate_report(payload)
