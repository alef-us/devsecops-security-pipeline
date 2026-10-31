# Security policy

This project is an educational example, not a production service. Please do not
include real credentials or sensitive data in issues, pull requests, or logs.

## Reporting a vulnerability

Use GitHub's private security advisory process for a suspected vulnerability.
If that is unavailable, contact the repository owner privately through GitHub.
Do not disclose exploitable details publicly until a fix or mitigation is available.

## Security gates

- The static analysis gate blocks a Bandit finding whose severity and confidence
  are both `MEDIUM` or higher, and blocks any finding whose severity label the
  gate cannot interpret. Lower findings are reported for manual triage.
- pip-audit blocks any declared or installed package version that has a known
  advisory. pip-audit publishes no severity rating, so the gate does not invent
  one; the fix is to upgrade the package.
- Gitleaks blocks every match, scanning commit history as well as the working
  tree. Values are redacted, so a detected secret is never written to a log, an
  artifact, or the job summary. A fake credential used for a negative test is
  generated in a temporary directory and is never committed.
- A control that cannot run exits with code 2 and fails the build. An unavailable
  scanner is never reported as a pass.
- No finding is suppressed without a written justification. `.gitleaks.toml`
  currently defines no allowlist entries.
- Ambiguous findings require manual investigation. Deleting a secret from the
  latest commit does not remove it from Git history; rotate a real credential and
  rewrite history only through an agreed repository-maintenance process.

Passing these checks does not prove that the application is secure.
