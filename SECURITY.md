# Security policy

This project is an educational example, not a production service. Please do not
include real credentials or sensitive data in issues, pull requests, or logs.

## Reporting a vulnerability

Use GitHub's private security advisory process for a suspected vulnerability.
If that is unavailable, contact the repository owner privately through GitHub.
Do not disclose exploitable details publicly until a fix or mitigation is available.

## Security gates

- Bandit blocks findings in production code using its default high-confidence rules.
- pip-audit blocks an unavailable scan or a vulnerability found in the declared
  dependency set; the repository currently has no runtime dependencies.
- Gitleaks blocks detected secrets. A fake credential used for a negative test must
  be generated in a temporary directory and never committed.
- Ambiguous findings require manual investigation. Deleting a secret from the
  latest commit does not remove it from Git history; rotate a real credential and
  rewrite history only through an agreed repository-maintenance process.

Passing these checks does not prove that the application is secure.
