"""The documented security policy, expressed as code.

Keeping the thresholds in one module means the README, SECURITY.md, and the
pipeline cannot drift apart silently: the tests assert the behaviour described
in the documentation.
"""

from __future__ import annotations

from security_gate.models import ControlResult, ControlStatus, Finding, Severity

#: A static-analysis finding blocks the build when both its severity and its
#: confidence reach this level. Low-confidence findings are reported for manual
#: triage instead of blocking, because this project treats a noisy gate that
#: developers learn to bypass as worse than a gate with a documented threshold.
SAST_BLOCKING_SEVERITY = Severity.MEDIUM
SAST_BLOCKING_CONFIDENCE = Severity.MEDIUM


def is_blocking_sast_finding(finding: Finding) -> bool:
    """Return True when a static-analysis finding violates the policy.

    UNKNOWN is deliberately treated as blocking. If the gate cannot interpret a
    label it must not assume the finding is harmless.
    """
    severity_blocks = (
        finding.severity is Severity.UNKNOWN or finding.severity >= SAST_BLOCKING_SEVERITY
    )
    confidence_blocks = (
        finding.confidence is Severity.UNKNOWN or finding.confidence >= SAST_BLOCKING_CONFIDENCE
    )
    return severity_blocks and confidence_blocks


def is_blocking_dependency_finding(finding: Finding) -> bool:
    """Return True when a dependency finding violates the policy.

    pip-audit reports whether a package version is affected by a known advisory,
    but it does not attach a severity rating. Inventing one would be dishonest,
    so this project uses a simple, defensible rule for its small dependency set:
    any package version with a known advisory blocks the build. The remediation
    is to upgrade the package, not to lower the threshold.
    """
    del finding  # The rule intentionally does not depend on scanner labels.
    return True


def is_blocking_secret_finding(finding: Finding) -> bool:
    """Return True when a secret finding violates the policy.

    Every match blocks. A credential that reaches version control must be
    treated as compromised and rotated, so there is no threshold to tune. False
    positives are handled by documenting a justified allowlist entry in
    ``.gitleaks.toml``, never by lowering this rule.
    """
    del finding  # Every match blocks, regardless of scanner labels.
    return True


def overall_exit_code(results: list[ControlResult]) -> int:
    """Translate control results into a process exit code.

    An unavailable scanner is a failure, never a pass. A build must not go green
    because a security tool could not run.
    """
    if any(result.status is ControlStatus.UNAVAILABLE for result in results):
        return EXIT_CONTROL_UNAVAILABLE
    if any(result.status is ControlStatus.FAILED for result in results):
        return EXIT_POLICY_VIOLATION
    return EXIT_OK


EXIT_OK = 0
EXIT_POLICY_VIOLATION = 1
EXIT_CONTROL_UNAVAILABLE = 2
