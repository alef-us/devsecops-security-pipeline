"""Tests for the security gate itself.

These are negative tests for the controls: they fail if a scanner silently stops
detecting a known-bad pattern, or if the gate stops returning a failing exit
code for a policy violation.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from security_gate import bandit_control, cli
from security_gate.models import ControlResult, ControlStatus, Finding, Severity
from security_gate.policy import (
    EXIT_CONTROL_UNAVAILABLE,
    EXIT_OK,
    EXIT_POLICY_VIOLATION,
    is_blocking_sast_finding,
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
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "summary.md"
            exit_code = cli.main(["--control", "sast", "--summary-file", str(target)])
            self.assertEqual(exit_code, EXIT_OK)
            self.assertIn("Security gate summary", target.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
