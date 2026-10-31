# DevSecOps security pipeline

An educational Python project demonstrating automated application testing, static
analysis, dependency auditing, secret detection, and secure GitHub Actions
configuration. The application is deliberately small so the pipeline remains the
main subject.

## Architecture

```text
HTTP client -> Python standard-library service -> validated JSON response

security_gate (policy engine)
  |-- sast control         -> Bandit    -> normalised findings -> policy -> exit code
  |-- dependencies control -> pip-audit -> normalised findings -> policy -> exit code
  |-- secrets control      -> Gitleaks  -> normalised findings -> policy -> exit code
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
python -m security_gate --control dependencies
python -m security_gate --control secrets
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

### Dependency policy

pip-audit audits the **installed environment**, not just the requirements files,
because the requirements files list only direct dependencies while the resolved
environment is what actually runs.

pip-audit does not attach a severity rating to an advisory, so the gate does not
invent one. For a dependency set this small the rule is simple and defensible:
**any package version with a known advisory blocks the build.** The remediation
is to upgrade the package, never to lower the threshold.

A non-zero pip-audit exit with no parsed findings, an unparsable report, or a
report without a dependency list is treated as `UNAVAILABLE` (exit code 2). This
matters because an unreachable vulnerability database otherwise looks exactly
like a clean scan.

#### Worked example from this repository

The first run of this control was not clean. It reported seven advisories:

| Package | Version | Advisories | Resolution |
|---|---|---|---|
| `pip` | 25.0.1 | 6, including PYSEC-2026-196 / CVE-2026-8643 | Upgrade; CI already installs the latest pip |
| `pytest` | 8.3.5 | PYSEC-2026-1845 | Pinned to `pytest==9.0.3` in `requirements-dev.txt` |

To investigate a dependency finding: read the advisory behind the identifier and
its aliases, check whether your code reaches the affected code path, prefer the
lowest release listed in `fix_versions`, re-run the control to confirm the
advisory is gone, and run the test suite to confirm the upgrade broke nothing.
If no fix exists, the finding needs a documented, reviewed decision rather than
a silent suppression.

### Secret detection policy

Gitleaks scans the repository **including its commit history**, so CI checks out
with `fetch-depth: 0`. This matters: deleting a credential from the latest
commit does not remove it from the commits that came before, and a shallow
clone would hide exactly that case.

Every match blocks. A credential that reaches version control must be treated as
compromised, so there is no threshold to tune. The order of remediation is:

1. **Rotate the credential first.** Until it is revoked, the leak is live.
2. Remove it from the working tree and replace it with a secret store or an
   environment variable supplied at runtime.
3. Only then consider rewriting history, through an agreed maintenance process.
   Rewriting history alone is not a fix, because the old commit may already have
   been cloned, cached, or forked.

Gitleaks always runs with `--redact`, and the gate never reads the `Secret`
field of a report. A detected value is therefore not written to a log, an
artifact, or the job summary. `tests/test_security_gate.py` asserts this.

**Handling a false positive.** Confirm the string cannot authenticate anywhere,
then add a narrow, commented allowlist entry to `.gitleaks.toml` naming the file
and the reason. Never widen a rule, disable the control, or allowlist a whole
directory. `.gitleaks.toml` currently defines no allowlist entries, because
nothing has needed one.

#### Proving the control works

The fake credential is **generated in a temporary directory at test time and is
never committed**, so the repository stays clean while the control is still
proven to work. It is structurally valid but uses sequential placeholder
characters and cannot authenticate to any service. The tests assert that
Gitleaks reports it, that a clean directory passes, that the repository history
is clean, and that the fake value never appears in the rendered summary.

The credential is also **assembled at runtime from separate parts** rather than
stored as a literal. That is not cosmetic: an earlier version of this test held
the value as a plain string, and GitHub push protection rejected the push. That
is the correct outcome, and the right response was to stop storing a
credential-shaped literal, not to click the bypass link. The repository now
passes two independent secret controls rather than one.

#### Installing Gitleaks

CI downloads the pinned release and verifies its published SHA-256 checksum
before use, so a tampered archive fails the build instead of running. Locally,
install Gitleaks on `PATH` or point `GITLEAKS_PATH` at the binary; the control
reports `UNAVAILABLE` rather than passing when it cannot find one.

## CI workflow

`.github/workflows/security.yml` runs on pushes to `main` and pull requests. It
checks out source with full history, installs pinned development tools, installs
a checksum-verified Gitleaks binary, runs unit tests, runs the security gate
(static analysis, dependency auditing, and secret detection), validates workflow
permissions, and uploads the security summary.
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
