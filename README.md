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
  |-- workflows control    -> zizmor    -> normalised findings -> policy -> exit code
  +-- summary -> GitHub step summary + artifact

CodeQL runs as a separate workflow and reports to GitHub code scanning.
Dependabot proposes dependency and action updates, which must pass the gate.
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

Bandit, pip-audit, and zizmor are installed by `requirements-dev.txt`. Gitleaks
is a standalone binary and is not on PyPI; download the release that matches
your platform, verify its published SHA-256 checksum, and either put it on
`PATH`, place it in `.tools/`, or point `GITLEAKS_PATH` at it. The CI workflow
does exactly that, checksum included. Without it the `secrets` control reports
`UNAVAILABLE`, which is a failure rather than a pass.

## Security checks

```powershell
python -m security_gate            # all controls, policy applied, exit code set
python -m security_gate --control sast
python -m security_gate --control dependencies
python -m security_gate --control secrets
python -m security_gate --control workflows
```

Gate exit codes:

| Code | Meaning |
|---|---|
| 0 | Every control passed the documented policy |
| 1 | A control reported a finding that violates the policy |
| 2 | A control could not run; this is a failure, never a pass |

### Example output

A passing run. The eight `LOW`/`HIGH` findings are genuine — these modules do
call `subprocess` — and are reported rather than suppressed, because hiding a
true finding to get a clean report is how a gate stops being useful:

```text
# Security gate summary

| Control | Status | Detail |
|---|---|---|
| dependencies | PASS | No known vulnerabilities in 35 scanned package(s). |
| sast | PASS | No blocking findings. 8 finding(s) below the policy threshold require manual triage only. |
| secrets | PASS | No secrets detected. |
| workflows | PASS | No blocking findings. 0 finding(s) below the policy threshold require manual triage only. |

## Findings for manual triage

- sast: B404 [severity=LOW confidence=HIGH] security_gate/bandit_control.py:6 - Consider possible security implications associated with the subprocess module.
- sast: B603 [severity=LOW confidence=HIGH] security_gate/bandit_control.py:82 - subprocess call - check for execution of untrusted input.
...
```

A failing run. This is the real output from the first draft of this project's
own Dependabot configuration, which the workflow audit rejected:

```text
# Security gate summary

| Control | Status | Detail |
|---|---|---|
| workflows | FAIL | 2 workflow finding(s) violate the policy. |

## Blocking findings

- workflows: dependabot-cooldown [severity=MEDIUM confidence=HIGH] .github/dependabot.yml:8 (insufficient implicit default-days (less than 7)) - insufficient cooldown in Dependabot updates
- workflows: dependabot-cooldown [severity=MEDIUM confidence=HIGH] .github/dependabot.yml:25 (insufficient implicit default-days (less than 7)) - insufficient cooldown in Dependabot updates
```

Exit code 1, so the step fails and the pipeline stops. The same summary is
written to the GitHub step summary and uploaded as an artifact, so a failure is
readable without opening the raw logs.

### Static analysis policy

A Bandit finding blocks the build when **both** its severity and its confidence
are `MEDIUM` or higher. A finding below that threshold is printed under
"Findings for manual triage" and does not block. An unrecognised severity label
blocks unconditionally, because a label the gate cannot interpret has not been
shown to be harmless — and a low confidence score is not allowed to rescue it.

The production scan currently reports eight low-severity Bandit findings
(`B404` and `B603`, one pair in each of the four control adapters under
`security_gate/`). They are genuine matches, not false positives: those modules
really do invoke `subprocess` in order to run the scanners. They do not block
because each command is a fixed argument list, is never passed through a shell,
and never includes user-controlled input. They are left visible rather than
suppressed so that the triage decision stays reviewable.

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

The same applies to an individual package. pip-audit marks a dependency it could
not resolve with `skip_reason` and still exits 0, so nothing in the exit code
reveals it. The gate inspects every entry and reports `UNAVAILABLE` if any
package was skipped: a package that was not audited has not been proven clean,
and counting it as clean would be exactly the false green this gate exists to
prevent.

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

### Workflow audit policy

The workflow itself is attack surface, so it is audited with
[zizmor](https://docs.zizmor.sh/). A workflow finding blocks when its severity
is `MEDIUM` or higher, **regardless of the scanner's confidence**. That is
stricter than the static analysis rule on purpose: the workflow surface is small
and changes rarely, so reviewing a low-confidence finding costs minutes, while a
missed workflow weakness exposes the job token to every later step. The audit
covers both workflow files and `.github/dependabot.yml`.

This control replaced an earlier step that asserted the workflow file contained
the strings `permissions:` and `contents: read`. That check could not fail in
any useful way, because it passed as long as the text appeared anywhere in the
file, including inside a comment.

#### What the audit found here

The first real run was not clean. zizmor reported `artipacked`: `actions/checkout`
persists the job token in `.git/config` by default, where a later step or an
uploaded artifact can expose it. No step in this workflow pushes to the
repository, so the fix was `persist-credentials: false`.

#### Hardening applied to the workflow

| Risk | Mitigation |
|---|---|
| Excessive token scope | `permissions: contents: read` at workflow **and** job level |
| Credential persistence | `persist-credentials: false` on checkout |
| Supply-chain tampering in actions | Every action pinned to a full commit SHA with its release in a comment |
| Supply-chain tampering in binaries | Gitleaks archive verified against its published SHA-256 checksum |
| Untrusted pull-request code | Triggered by `pull_request`, never `pull_request_target`; no secrets are exposed to any step |
| Script injection | No `${{ }}` expansion of event data into a shell command |
| Unpinned runner | Pinned to `ubuntu-24.04` rather than `ubuntu-latest` |

zizmor runs with `--offline`, so it needs no token and no network, and its
result is reproducible. The audits that require the GitHub API are skipped as a
result; `unpinned-uses`, `template-injection`, `dangerous-triggers`, and
`excessive-permissions` all run offline.

zizmor maps severity onto distinct exit codes, which makes "a finding was
reported" indistinguishable from "the tool crashed". The control therefore runs
it with `--no-exit-codes` and decides from the JSON report, so a non-zero exit
unambiguously means the tool failed.

#### Proving the control works

The tests write a deliberately insecure workflow to a temporary directory and
assert that zizmor reports `dangerous-triggers`, `template-injection`,
`unpinned-uses`, and `excessive-permissions`, and that the gate returns a
failing exit code. The fixture is never committed under `.github/workflows`,
because GitHub would then schedule it.

## CI workflow

`.github/workflows/security.yml` runs on pushes to `main` and pull requests. It
checks out source with full history, installs pinned development tools, installs
a checksum-verified Gitleaks binary, runs unit tests, runs the security gate
(static analysis, dependency auditing, secret detection, and workflow
auditing), and uploads the security summary.

`.github/workflows/codeql.yml` runs CodeQL separately, on pushes, pull requests,
and a weekly schedule. It complements Bandit rather than duplicating it: Bandit
matches known-bad patterns within a single file, while CodeQL performs data-flow
analysis across the project and can follow untrusted input from an entry point
to a sink. It is a separate workflow because it needs `security-events: write`
to upload results, and the security gate must not hold that permission.

The weekly schedule matters: a scanner's rules change even when the code does
not, so a repository that only scans on push stops being re-evaluated the moment
development pauses.

### Dependabot

`.github/dependabot.yml` keeps the Python tooling and the action pins current.
It is configured conservatively, because an update bot is itself a supply-chain
path into the repository:

- **Weekly**, not daily, and limited to three open pull requests per ecosystem.
- **A seven-day cooldown** before adopting a freshly published release. A
  compromised package is usually caught in the first days after publication.
- **Security tooling is grouped** into one pull request, so the review is one
  coherent change instead of three competing ones.
- Every update still has to pass the full security gate before it can merge, and
  an action pin is only ever moved to another commit SHA.

The cooldown was not in the first draft of that file. This project's own
workflow audit reported `dependabot-cooldown` against it, which is the gate
doing its job on configuration the author had just written.
The workflow has read-only repository contents permission; no secrets are exposed
to application steps. All third-party actions are pinned to full commit SHAs, with
the corresponding release recorded in a trailing comment.

The workflow fails if tests or mandatory security checks fail. A scanner outage is
also a failure; it must not be interpreted as a clean result.

## Threat model

See [THREAT_MODEL.md](./THREAT_MODEL.md) for assets, trust boundaries,
attackers, the fourteen threats this pipeline addresses, and — just as
important — the residual risks it does not.

| Area | Summary |
|---|---|
| Assets | Source code integrity, the CI job token, dependency and action integrity, scanner results, developer credentials |
| Trust boundaries | Workstation to GitHub, pull request to runner, public internet to runner, runner to GitHub API |
| Potential attackers | Opportunistic contributor, compromised upstream maintainer, secret harvester, careless maintainer |
| Main threats | Unsafe code pattern, vulnerable dependency, leaked credential, stolen job token, malicious action version, a scanner that silently stops working |
| Mitigations | Input validation, four blocking controls, CodeQL, least-privilege permissions, SHA-pinned actions, checksum-verified binaries, Dependabot cooldown, negative tests |
| Residual risks | Scanner false negatives, logic and authorisation flaws, advisory lag, transitive supply-chain compromise, no runtime testing |

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

Three decisions are worth defending in particular:

- **The policy lives in code, not in the workflow.** `security_gate/policy.py`
  is the only place a threshold is defined, so the documentation and the
  pipeline cannot drift apart.
- **Unavailable is not a pass.** A missing or crashed scanner exits 2 and fails
  the build. The most dangerous failure mode of a security pipeline is a green
  check that proved nothing.
- **Every control has a negative test.** A scanner that silently stops matching
  is indistinguishable from a clean repository, so each control is tested
  against a known-bad fixture rather than trusted.

Each of the four scanners also caught something real here: an outdated `pip` and
`pytest` with published advisories, a job token persisted by `actions/checkout`,
a credential-shaped literal that GitHub push protection blocked before it
landed, and a missing Dependabot cooldown in a file written while building this
pipeline.
