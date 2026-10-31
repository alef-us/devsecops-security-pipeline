# DevSecOps security pipeline

An educational Python project demonstrating automated application testing, static
analysis, dependency auditing, secret detection, and secure GitHub Actions
configuration. The application is deliberately small so the pipeline remains the
main subject.

## Architecture

```text
HTTP client -> Python standard-library service -> validated JSON response

security_gate (policy engine)
  |-- sast control -> Bandit -> normalised findings -> policy -> exit code
  +-- summary -> GitHub step summary + artifact
```

The service exposes `GET /health` and `GET /hello?name=...`. It has no database,
authentication, external service, container, or production credential.

Scanner output is normalised into a shared finding model before the policy is
applied, so the thresholds live in one place (`security_gate/policy.py`) instead
of being spread across workflow steps.

## Local setup

Requires Python 3.12 or newer.

```powershell
python -m venv .venv
. .venv/Scripts/Activate.ps1
python -m pip install -r requirements-dev.txt
python -m pytest
python app.py
```

Then request `http://127.0.0.1:8000/health` or
`http://127.0.0.1:8000/hello?name=Alice`.

## Security checks

```powershell
python -m security_gate            # all controls, policy applied, exit code set
python -m security_gate --control sast
python -m pip_audit -r requirements.txt
gitleaks detect --config .gitleaks.toml --no-banner
```

Gate exit codes:

| Code | Meaning |
|---|---|
| 0 | Every control passed the documented policy |
| 1 | A control reported a finding that violates the policy |
| 2 | A control could not run; this is a failure, never a pass |

### Static analysis policy

A Bandit finding blocks the build when **both** its severity and its confidence
are `MEDIUM` or higher. A finding below that threshold is printed under
"Findings for manual triage" and does not block. An unrecognised severity label
is treated as blocking, because a label the gate cannot interpret has not been
shown to be harmless.

The production scan currently reports two low-severity Bandit findings
(`B404` and `B603`) in `security_gate/bandit_control.py`. They are genuine
matches, not false positives: the module really does invoke `subprocess`. They
do not block because the command is a fixed argument list, is never passed
through a shell, and never includes user-controlled input. They are left visible
rather than suppressed so that the triage decision stays reviewable.

### Proving the control works

`tests/fixtures/insecure_example.py` is an isolated negative-test fixture
containing a real `subprocess` call with `shell=True`. It is never imported by
the application, never executed by the tests, and never served. The suite in
`tests/test_security_gate.py` asserts that Bandit reports `B602` for it, that
the gate returns a non-zero exit code, and that the fixture is excluded from the
production scan. If a scanner silently stops detecting the pattern, those tests
fail.

```powershell
python -m pytest tests/test_security_gate.py -v
```

## CI workflow

`.github/workflows/security.yml` runs on pushes to `main` and pull requests. It
checks out source, installs pinned development tools, runs unit tests, runs the
static analysis security gate, runs pip-audit, runs Gitleaks, validates workflow
permissions, and uploads the security summary and scanner reports.
The workflow has read-only repository contents permission; no secrets are exposed
to application steps. All third-party actions are pinned to full commit SHAs, with
the corresponding release recorded in a trailing comment.

The workflow fails if tests or mandatory security checks fail. A scanner outage is
also a failure; it must not be interpreted as a clean result.

## Threat model

| Area | Summary |
|---|---|
| Assets | Source code, dependency integrity, CI token, scanner reports |
| Trust boundaries | Developer workstation, GitHub repository, pull-request workflow, runner |
| Potential attackers | Malicious contributor, dependency maintainer, compromised action, accidental secret commit |
| Main threats | Injection in user input, vulnerable dependency, leaked credential, workflow supply-chain abuse |
| Mitigations | Strict input validation, unit tests, Bandit, pip-audit, Gitleaks, least-privilege permissions, SHA-pinned actions |
| Residual risks | Tool false negatives, action release risk, transitive supply-chain compromise, unreviewed logic flaws |

## Triage and limitations

Automated severity labels are not a substitute for review. Investigate the code
path, exploitability, reachability, and remediation before suppressing a finding.
Bandit does not find every logic or business flaw; pip-audit depends on its
vulnerability database; Gitleaks can miss novel secret formats; none of these
tools replaces review or runtime testing. No claim is made that a passing run
means the application is completely secure.

## Interview takeaways

This repository demonstrates incremental security gates, negative tests for the
controls themselves, explicit workflow permissions, reproducible tool versions,
safe handling of false positives, and honest reporting of scanner limitations.
