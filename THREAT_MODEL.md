# Threat model

This is a deliberately small threat model for a deliberately small project. Its
purpose is to show how the controls in the pipeline map onto specific threats,
and to be honest about what is left unmitigated.

The subject is the **repository and its pipeline**, not a production service.
The application exists so that the pipeline has something to scan.

## Assets

| Asset | Why it matters |
|---|---|
| Source code integrity | A malicious change that reaches `main` is trusted by everyone who clones the repository |
| The `GITHUB_TOKEN` issued to a workflow run | Can write to the repository if its permissions allow |
| Dependency and action integrity | Code from a package or an action runs with the same privileges as the job |
| Scanner results | A result that is wrong or silently skipped produces false assurance |
| Developer credentials | A leaked credential grants whatever access it carries, immediately |

The application itself holds no user data, no credentials, and no secrets. That
is a design decision, not an oversight: there is nothing to steal from it.

## Trust boundaries

1. **Developer workstation → GitHub.** Code and credentials cross on push. Push
   protection and the secret control both sit on this boundary.
2. **Pull request → CI runner.** A pull request from a fork is untrusted input.
   The workflow is triggered by `pull_request`, which runs without repository
   secrets and with a read-only token.
3. **Public internet → CI runner.** Dependencies, action code, the Gitleaks
   binary, and vulnerability data all come from outside.
4. **CI runner → GitHub API.** The job token is the only credential present.

## Potential attackers

| Attacker | Capability |
|---|---|
| Opportunistic contributor | Opens a pull request containing malicious code or a malicious workflow change |
| Compromised upstream maintainer | Publishes a malicious version of a dependency or an action |
| Secret harvester | Scans public repositories and history for credentials, usually within minutes of a push |
| Careless maintainer | Commits a credential, or merges a finding without reading it |

A targeted attacker with GitHub account access is out of scope: at that point
the account, not the pipeline, is the control that failed.

## Threats and mitigations

| # | Threat | Mitigation | Control |
|---|---|---|---|
| 1 | Unsafe pattern reaches `main` (command injection, unsafe deserialisation) | Bandit blocks at `MEDIUM`/`MEDIUM`; CodeQL adds cross-file data-flow analysis | `sast`, CodeQL |
| 2 | Known-vulnerable dependency ships | Any package version with a known advisory blocks the build | `dependencies` |
| 3 | Credential committed to the repository | Gitleaks scans the full history; GitHub push protection blocks before the push lands | `secrets` + push protection |
| 4 | Credential already in older commits | `fetch-depth: 0`, so history is scanned, not just the tip | `secrets` |
| 5 | Secret leaked through CI logs or artifacts | `--redact` always on; the gate never reads the `Secret` field; only the summary is uploaded | `secrets` |
| 6 | Job token stolen from the checkout | `persist-credentials: false` | `workflows` |
| 7 | Workflow escalates its own privileges | Explicit `permissions: contents: read` at workflow and job level | `workflows` |
| 8 | Script injection via pull-request data | No `${{ }}` expansion of event data into a shell; `pull_request`, never `pull_request_target` | `workflows` |
| 9 | Malicious action version | Every action pinned to a full commit SHA | `workflows` |
| 10 | Tampered scanner binary | Gitleaks archive verified against its published SHA-256 checksum | Install step |
| 11 | Malicious dependency adopted immediately after publication | Seven-day Dependabot cooldown | Dependabot |
| 12 | A scanner silently stops detecting anything | Negative tests assert each control still reports a known-bad fixture | Test suite |
| 13 | A scanner is unavailable and the build goes green | Unavailable is exit code 2 and fails the build | `security_gate.policy` |
| 14 | Invalid user input reaches application logic | Allowlist validation with a length bound, and tests for the rejection paths | Application |

## Residual risks

These are **not** mitigated, and no claim is made otherwise.

- **False negatives.** Every scanner here matches known patterns or known
  advisories. A novel vulnerability, a novel secret format, or a logic flaw
  specific to this application will not be reported by any of them.
- **Business-logic and authorisation flaws.** No tool in this pipeline can find
  them, because it does not know what the application is supposed to do.
- **Transitive supply-chain compromise.** A pinned SHA guarantees you get the
  same code every time. It does not guarantee that code was safe when it was
  pinned.
- **Advisory lag.** A dependency is reported only once an advisory is published.
  The window between exploitation and publication is uncovered.
- **The cooldown is a trade-off.** Waiting seven days to adopt a release also
  delays legitimate security fixes by up to seven days.
- **No runtime testing.** There is no DAST, no fuzzing, and no runtime
  monitoring, so nothing here observes the application while it executes.
- **Trust in the GitHub platform.** The runner, the token issuance, and push
  protection are all assumed to behave correctly.
- **The policy thresholds are judgement calls.** A `LOW`/`LOW` Bandit finding
  that is genuinely exploitable would not block this build.

## What would change for a production service

This model deliberately stops at the repository boundary. A real service would
add authentication and authorisation threats, data-at-rest and data-in-transit
concerns, tenant isolation, rate limiting and abuse, secret management and
rotation, runtime monitoring, incident response, and dynamic testing against a
deployed environment. None of that is in scope here, and the pipeline should not
be read as evidence that any of it has been addressed.
