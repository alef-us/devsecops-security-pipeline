"""Command line entry point that runs the security controls and enforces policy."""

from __future__ import annotations

import argparse
import os
from collections.abc import Callable, Sequence
from pathlib import Path

from security_gate import bandit_control, pip_audit_control
from security_gate.models import ControlResult, ControlStatus
from security_gate.policy import overall_exit_code

#: Registry of available controls. Later stages register additional scanners here.
CONTROLS: dict[str, Callable[[], ControlResult]] = {
    bandit_control.CONTROL_NAME: bandit_control.scan,
    pip_audit_control.CONTROL_NAME: pip_audit_control.scan,
}

_STATUS_MARKER = {
    ControlStatus.PASSED: "PASS",
    ControlStatus.FAILED: "FAIL",
    ControlStatus.UNAVAILABLE: "UNAVAILABLE",
}


def render_summary(results: Sequence[ControlResult]) -> str:
    """Render a concise, log-safe summary of every control that ran."""
    lines = ["# Security gate summary", "", "| Control | Status | Detail |", "|---|---|---|"]
    for result in results:
        detail = result.detail.replace("|", "\\|")
        lines.append(f"| {result.name} | {_STATUS_MARKER[result.status]} | {detail} |")

    blocking = [finding for result in results for finding in result.blocking_findings]
    if blocking:
        lines.extend(["", "## Blocking findings", ""])
        lines.extend(f"- {finding.summary_line()}" for finding in blocking)

    informational = [
        finding
        for result in results
        for finding in result.findings
        if finding not in result.blocking_findings
    ]
    if informational:
        lines.extend(["", "## Findings for manual triage", ""])
        lines.extend(f"- {finding.summary_line()}" for finding in informational)

    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-gate",
        description="Run the project security controls and apply the documented policy.",
    )
    parser.add_argument(
        "--control",
        action="append",
        choices=sorted(CONTROLS),
        help="Run only the named control. May be repeated. Defaults to every control.",
    )
    parser.add_argument(
        "--summary-file",
        type=Path,
        default=None,
        help=(
            "Append the Markdown summary to this file, in addition to the GitHub "
            "step summary when running in CI."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the selected controls and return the process exit code."""
    arguments = build_parser().parse_args(argv)
    selected = arguments.control or sorted(CONTROLS)
    results = [CONTROLS[name]() for name in selected]

    summary = render_summary(results)
    print(summary, end="")

    targets: list[Path] = []
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        targets.append(Path(os.environ["GITHUB_STEP_SUMMARY"]))
    if arguments.summary_file is not None:
        targets.append(arguments.summary_file)
    for target in targets:
        with target.open("a", encoding="utf-8") as handle:
            handle.write(summary)

    return overall_exit_code(list(results))
