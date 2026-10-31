# DevSecOps security pipeline

An educational Python project demonstrating automated application testing, static
analysis, dependency auditing, secret detection, and secure GitHub Actions
configuration. The application is deliberately small so the pipeline remains the
main subject.

## Architecture

```text
HTTP client -> Python standard-library service -> validated JSON response
                    |
                    +-> pytest
                    +-> Bandit
                    +-> pip-audit
                    +-> Gitleaks
```

The service exposes `GET /health` and `GET /hello?name=...`. It has no database,
authentication, external service, container, or production credential.

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
python -m bandit -r app.py -f json -o bandit-report.json
python -m pip_audit -r requirements.txt
gitleaks detect --config .gitleaks.toml --no-banner
```

The committed application is expected to pass. `security/demo_vulnerable.py` is
an isolated negative-test fixture and is intentionally not scanned by the CI
production-code command. To demonstrate detection locally:

```powershell
python -m bandit security/demo_vulnerable.py
```

For secret detection, create a temporary file containing an obviously fake
credential (for example `not-a-real-credential-for-tests`) and run Gitleaks
against that temporary directory. Never commit the fixture.

## CI workflow

`.github/workflows/security.yml` runs on pushes to `main` and pull requests. It
checks out source, installs pinned development tools, runs unit tests, runs Bandit
and pip-audit, runs Gitleaks, validates workflow permissions, and uploads reports.
The workflow has read-only repository contents permission; no secrets are exposed
to application steps. Third-party actions are pinned to immutable commit SHAs
where available. The Gitleaks action currently uses its documented release tag
because its action release is managed separately from the scanner binary.

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
