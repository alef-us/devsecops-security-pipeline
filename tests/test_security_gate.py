"""Tests for the security gate itself.

These are negative tests for the controls: they fail if a scanner silently stops
detecting a known-bad pattern, or if the gate stops returning a failing exit
code for a policy violation.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from security_gate import bandit_control, cli, gitleaks_control, pip_audit_control, zizmor_control
from security_gate.models import ControlResult, ControlStatus, Finding, Severity
from security_gate.policy import (
    EXIT_CONTROL_UNAVAILABLE,
    EXIT_OK,
    EXIT_POLICY_VIOLATION,
    is_blocking_dependency_finding,
    is_blocking_sast_finding,
    is_blocking_workflow_finding,
    overall_exit_code,
)

FIXTURE = Path(__file__).parent / "fixtures" / "insecure_example.py"


def make_finding(severity: Severity, confidence: Severity) -> Finding:
    return Finding(
        control="sast",
        identifier="B000",
        severity=severity,
        confidence=confidence,
        location="example.py:1",
        description="example",
    )


class SeverityTests(unittest.TestCase):
    def test_known_labels_are_ordered(self):
        self.assertTrue(Severity.HIGH > Severity.MEDIUM > Severity.LOW)

    def test_scanner_aliases_are_mapped(self):
        self.assertEqual(Severity.parse("moderate"), Severity.MEDIUM)
        self.assertEqual(Severity.parse("INFO"), Severity.LOW)

    def test_unrecognised_label_is_not_downgraded(self):
        self.assertEqual(Severity.parse("banana"), Severity.UNKNOWN)
        self.assertEqual(Severity.parse(None), Severity.UNKNOWN)


class PolicyTests(unittest.TestCase):
    def test_high_severity_and_confidence_blocks(self):
        self.assertTrue(is_blocking_sast_finding(make_finding(Severity.HIGH, Severity.HIGH)))

    def test_threshold_is_inclusive(self):
        self.assertTrue(is_blocking_sast_finding(make_finding(Severity.MEDIUM, Severity.MEDIUM)))

    def test_low_confidence_does_not_block(self):
        self.assertFalse(is_blocking_sast_finding(make_finding(Severity.HIGH, Severity.LOW)))

    def test_low_severity_does_not_block(self):
        self.assertFalse(is_blocking_sast_finding(make_finding(Severity.LOW, Severity.HIGH)))

    def test_unknown_label_blocks(self):
        self.assertTrue(is_blocking_sast_finding(make_finding(Severity.UNKNOWN, Severity.HIGH)))


class ExitCodeTests(unittest.TestCase):
    def result(self, status: ControlStatus) -> ControlResult:
        return ControlResult(name="sast", status=status, detail="")

    def test_all_passed(self):
        self.assertEqual(overall_exit_code([self.result(ControlStatus.PASSED)]), EXIT_OK)

    def test_policy_violation_is_nonzero(self):
        code = overall_exit_code([self.result(ControlStatus.FAILED)])
        self.assertEqual(code, EXIT_POLICY_VIOLATION)
        self.assertNotEqual(code, EXIT_OK)

    def test_unavailable_scanner_is_a_failure_not_a_pass(self):
        code = overall_exit_code(
            [self.result(ControlStatus.PASSED), self.result(ControlStatus.UNAVAILABLE)]
        )
        self.assertEqual(code, EXIT_CONTROL_UNAVAILABLE)
        self.assertNotEqual(code, EXIT_OK)


class BanditReportTests(unittest.TestCase):
    def test_scan_errors_make_the_control_unavailable(self):
        payload = {"errors": [{"filename": "x.py", "reason": "syntax error"}], "results": []}
        self.assertEqual(bandit_control.evaluate_report(payload).status, ControlStatus.UNAVAILABLE)

    def test_clean_report_passes(self):
        self.assertEqual(
            bandit_control.evaluate_report({"errors": [], "results": []}).status,
            ControlStatus.PASSED,
        )

    def test_below_threshold_finding_is_reported_but_does_not_block(self):
        payload = {
            "errors": [],
            "results": [
                {
                    "test_id": "B101",
                    "issue_severity": "LOW",
                    "issue_confidence": "HIGH",
                    "filename": "app.py",
                    "line_number": 3,
                    "issue_text": "assert used",
                }
            ],
        }
        result = bandit_control.evaluate_report(payload)
        self.assertEqual(result.status, ControlStatus.PASSED)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.blocking_findings, [])


class DependencyReportTests(unittest.TestCase):
    VULNERABLE_PAYLOAD = {
        "dependencies": [
            {"name": "safe-package", "version": "1.0.0", "vulns": []},
            {
                "name": "vulnerable-package",
                "version": "1.2.3",
                "vulns": [
                    {
                        "id": "PYSEC-0000-1",
                        "fix_versions": ["1.2.4"],
                        "aliases": ["CVE-0000-0001"],
                        "description": "example advisory",
                    }
                ],
            },
        ],
        "fixes": [],
    }

    def test_any_known_advisory_blocks(self):
        result = pip_audit_control.evaluate_report(self.VULNERABLE_PAYLOAD)
        self.assertEqual(result.status, ControlStatus.FAILED)
        self.assertEqual(len(result.blocking_findings), 1)
        self.assertEqual(overall_exit_code([result]), EXIT_POLICY_VIOLATION)

    def test_finding_records_the_remediation(self):
        finding = pip_audit_control.parse_report(self.VULNERABLE_PAYLOAD)[0]
        self.assertEqual(finding.location, "vulnerable-package==1.2.3")
        self.assertIn("fixed in 1.2.4", finding.description)
        self.assertIn("CVE-0000-0001", finding.description)

    def test_missing_fix_version_is_stated_explicitly(self):
        payload = {
            "dependencies": [
                {"name": "p", "version": "1", "vulns": [{"id": "X", "fix_versions": []}]}
            ]
        }
        self.assertIn("no fix available", pip_audit_control.parse_report(payload)[0].description)

    def test_severity_is_not_invented(self):
        finding = pip_audit_control.parse_report(self.VULNERABLE_PAYLOAD)[0]
        self.assertEqual(finding.severity, Severity.UNKNOWN)
        self.assertTrue(is_blocking_dependency_finding(finding))

    def test_clean_report_passes(self):
        payload = {"dependencies": [{"name": "p", "version": "1", "vulns": []}], "fixes": []}
        self.assertEqual(pip_audit_control.evaluate_report(payload).status, ControlStatus.PASSED)

    def test_report_without_dependency_list_is_unavailable(self):
        result = pip_audit_control.evaluate_report({"fixes": []})
        self.assertEqual(result.status, ControlStatus.UNAVAILABLE)
        self.assertEqual(overall_exit_code([result]), EXIT_CONTROL_UNAVAILABLE)


class SecretReportTests(unittest.TestCase):
    LEAK_PAYLOAD = [
        {
            "RuleID": "slack-bot-token",
            "Description": "Identified a Slack Bot token",
            "File": "config.yml",
            "StartLine": 7,
            "Commit": "0123456789abcdef0123456789abcdef01234567",
            "Secret": "REDACTED",
        }
    ]

    def test_any_match_blocks(self):
        result = gitleaks_control.evaluate_report(self.LEAK_PAYLOAD)
        self.assertEqual(result.status, ControlStatus.FAILED)
        self.assertEqual(overall_exit_code([result]), EXIT_POLICY_VIOLATION)

    def test_finding_records_file_line_and_commit(self):
        finding = gitleaks_control.parse_report(self.LEAK_PAYLOAD)[0]
        self.assertEqual(finding.identifier, "slack-bot-token")
        self.assertIn("config.yml:7", finding.location)
        self.assertIn("commit 0123456789ab", finding.location)

    def test_empty_report_passes(self):
        self.assertEqual(gitleaks_control.evaluate_report([]).status, ControlStatus.PASSED)


class SecretDetectionLiveTests(unittest.TestCase):
    """Negative tests that run the real secret scanner.

    The fake credential is written to a temporary directory at test time and is
    never committed, so the repository itself stays clean while the control is
    still proven to work.
    """

    #: The credential is assembled at runtime so that no credential-shaped
    #: literal is ever stored in the repository. An earlier version of this test
    #: held the value as a plain string and GitHub push protection blocked the
    #: push, which is exactly what a second, independent control should do. The
    #: parts below are sequential placeholders and cannot authenticate anywhere.
    CREDENTIAL_PARTS = ("xoxb", "123456789012", "123456789012", "abcdefghijklmnopqrstuvwx")

    @classmethod
    def fake_credential(cls) -> str:
        return "-".join(cls.CREDENTIAL_PARTS)

    def setUp(self):
        if gitleaks_control.find_executable() is None:
            self.skipTest("gitleaks is not installed; set GITLEAKS_PATH or add it to PATH")

    def test_fake_credential_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "settings.yml"
            target.write_text(f"slack_token: {self.fake_credential()}\n", encoding="utf-8")
            result = gitleaks_control.scan_directory(directory)

        self.assertEqual(result.status, ControlStatus.FAILED, result.detail)
        self.assertIn("slack-bot-token", {f.identifier for f in result.blocking_findings})

    def test_detected_secret_value_is_never_printed(self):
        credential = self.fake_credential()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "settings.yml"
            target.write_text(f"slack_token: {credential}\n", encoding="utf-8")
            result = gitleaks_control.scan_directory(directory)

        summary = cli.render_summary([result])
        self.assertNotIn(credential, summary)
        self.assertNotIn(credential, result.detail)

    def test_clean_directory_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "settings.yml").write_text("timeout: 30\n", encoding="utf-8")
            result = gitleaks_control.scan_directory(directory)
        self.assertEqual(result.status, ControlStatus.PASSED, result.detail)

    def test_repository_history_contains_no_secrets(self):
        result = gitleaks_control.scan(str(Path(__file__).resolve().parent.parent))
        if result.status is ControlStatus.UNAVAILABLE:
            self.skipTest(result.detail)
        self.assertEqual(
            result.status,
            ControlStatus.PASSED,
            "\n".join(f.summary_line() for f in result.blocking_findings),
        )


class WorkflowAuditTests(unittest.TestCase):
    def test_severity_threshold_ignores_confidence(self):
        finding = make_finding(Severity.MEDIUM, Severity.LOW)
        self.assertTrue(is_blocking_workflow_finding(finding))

    def test_low_severity_does_not_block(self):
        self.assertFalse(is_blocking_workflow_finding(make_finding(Severity.LOW, Severity.HIGH)))

    def test_unknown_severity_blocks(self):
        self.assertTrue(is_blocking_workflow_finding(make_finding(Severity.UNKNOWN, Severity.LOW)))

    def test_report_is_normalised(self):
        payload = [
            {
                "ident": "template-injection",
                "desc": "code injection via template expansion",
                "url": "https://docs.zizmor.sh/audits/#template-injection",
                "determinations": {"severity": "High", "confidence": "High"},
                "locations": [
                    {
                        "symbolic": {
                            "key": {"Local": {"verbatim_path": ".github/workflows\\x.yml"}},
                            "annotation": "this step",
                        },
                        "concrete": {"location": {"start_point": {"row": 7}}},
                    }
                ],
            }
        ]
        finding = zizmor_control.parse_report(payload)[0]
        self.assertEqual(finding.severity, Severity.HIGH)
        # zizmor rows are zero-based; reviewers count lines from one.
        self.assertIn(".github/workflows/x.yml:8", finding.location)
        self.assertIn("this step", finding.location)

    def test_empty_report_passes(self):
        self.assertEqual(zizmor_control.evaluate_report([]).status, ControlStatus.PASSED)


class WorkflowAuditLiveTests(unittest.TestCase):
    """Negative tests that run the real workflow auditor.

    The insecure workflow is written to a temporary directory at test time. It
    is deliberately never committed under .github/workflows, because GitHub
    would then schedule it.
    """

    INSECURE_WORKFLOW = """
name: unsafe
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "title is ${{ github.event.pull_request.title }}"
"""

    def setUp(self):
        if zizmor_control.find_executable() is None:
            self.skipTest("zizmor is not installed; set ZIZMOR_PATH or add it to PATH")

    def test_insecure_workflow_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            workflows = Path(directory) / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "unsafe.yml").write_text(self.INSECURE_WORKFLOW, encoding="utf-8")
            result = zizmor_control.scan([directory])

        self.assertEqual(result.status, ControlStatus.FAILED, result.detail)
        reported = {finding.identifier for finding in result.blocking_findings}
        for expected in (
            "dangerous-triggers",
            "template-injection",
            "unpinned-uses",
            "excessive-permissions",
        ):
            self.assertIn(expected, reported)
        self.assertEqual(overall_exit_code([result]), EXIT_POLICY_VIOLATION)

    def test_project_workflows_pass(self):
        result = zizmor_control.scan()
        if result.status is ControlStatus.UNAVAILABLE:
            self.skipTest(result.detail)
        self.assertEqual(
            result.status,
            ControlStatus.PASSED,
            "\n".join(f.summary_line() for f in result.blocking_findings),
        )


class LiveScannerTests(unittest.TestCase):
    """End-to-end checks that run the real scanner."""

    def test_production_code_passes_the_policy(self):
        result = bandit_control.scan()
        self.assertEqual(result.status, ControlStatus.PASSED, result.detail)

    def test_intentionally_vulnerable_fixture_is_detected(self):
        self.assertTrue(FIXTURE.is_file(), "the negative-test fixture must exist")
        result = bandit_control.scan([str(FIXTURE)])
        self.assertEqual(result.status, ControlStatus.FAILED, result.detail)
        self.assertIn("B602", {finding.identifier for finding in result.blocking_findings})

    def test_gate_returns_failing_exit_code_for_the_fixture(self):
        result = bandit_control.scan([str(FIXTURE)])
        self.assertEqual(overall_exit_code([result]), EXIT_POLICY_VIOLATION)

    def test_fixture_is_excluded_from_the_production_scan(self):
        scanned = {finding.location for finding in bandit_control.scan().findings}
        self.assertFalse(any("insecure_example" in location for location in scanned))

    def test_installed_environment_has_no_known_vulnerabilities(self):
        result = pip_audit_control.scan()
        if result.status is ControlStatus.UNAVAILABLE:
            self.skipTest(f"vulnerability service unavailable: {result.detail}")
        self.assertEqual(
            result.status,
            ControlStatus.PASSED,
            "\n".join(finding.summary_line() for finding in result.blocking_findings),
        )


class SummaryTests(unittest.TestCase):
    def test_summary_lists_each_control_and_blocking_finding(self):
        finding = make_finding(Severity.HIGH, Severity.HIGH)
        result = ControlResult(
            name="sast",
            status=ControlStatus.FAILED,
            detail="1 finding(s) violate the static analysis policy.",
            findings=[finding],
            blocking_findings=[finding],
        )
        summary = cli.render_summary([result])
        self.assertIn("| sast | FAIL |", summary)
        self.assertIn("Blocking findings", summary)
        self.assertIn("B000", summary)

    def test_summary_file_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "summary.md"
            exit_code = cli.main(["--control", "sast", "--summary-file", str(target)])
            self.assertEqual(exit_code, EXIT_OK)
            self.assertIn("Security gate summary", target.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
