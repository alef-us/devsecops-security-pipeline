"""Negative-test fixture for static analysis.

This module is never imported by the application, never executed by the test
suite, and never exposed as a running service. It exists only so the test suite
can prove that the static analysis control actually reports a known-bad pattern.
If this file stops being reported, the SAST control itself is broken.
"""

import subprocess


def run_user_command(user_supplied_command: str) -> int:
    """Intentionally insecure: Bandit must report B602 (subprocess with shell=True)."""
    completed = subprocess.run(user_supplied_command, shell=True, check=False)
    return completed.returncode
