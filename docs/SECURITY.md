# Security Policy

Keyorix is a self-hosted secrets manager: encryption at rest, authentication
(sessions, PAT, machine identities, OIDC, SAML SSO, TOTP MFA, WebAuthn/passkeys),
scoped RBAC, and a tamper-evident audit trail, deployed entirely inside your own
infrastructure. This document is the vulnerability disclosure policy and the
index into the rest of Keyorix's security documentation — for what's actually
implemented and how, see the linked documents below rather than this page,
which is deliberately short.

## Reporting a vulnerability

**Preferred: [GitHub private vulnerability reporting](https://github.com/keyorixhq/keyorix/security/advisories/new)**
on this repository — it keeps the report and any discussion private until a
fix ships, and lets you attach a proof of concept directly.

**Alternative:** email `security@keyorix.com`.

Please include: the affected version/commit, a description of the issue, and
reproduction steps or a proof of concept if you have one. Do not open a public
GitHub issue for a suspected vulnerability.

## Supported versions

Keyorix is **pre-1.0**. No formal support period is declared yet — this is
stated explicitly on every release, matching
[ADR-067](adr-067-release-lifecycle-support-policy.md)'s decision to distinguish
development tags (no declared support period, no Declaration of Conformity)
from a future designated release (v1.0 onward: a declared multi-year,
security-only support period, a Declaration of Conformity, a signed update
bundle, an SBOM and VEX document — see ADR-067 for the full lifecycle design).

In practice, security fixes today land on the latest release only — the same
scoping the published remediation commitment below assumes.

## Remediation timelines

Sized for the worst realistic month, not the best one — this is what you may
rely on. Full rationale, including how these numbers were benchmarked against
comparable projects, is in [ADR-104](adr-104-security-remediation-sla.md).

| Class | Commitment |
|---|---|
| Acknowledge a report | 48 hours |
| Initial assessment | 7 days |
| Fix, all severities | **≤90 days** from a validated report |
| High / Critical | **1 week advance notice** before the security release ships |
| Advisory | A GHSA with a requested CVE, published the **same day** as the fix |
| Supported versions | Latest release only |
| Release cadence | Not published (see ADR-104 for why) |

The 90-day ceiling applies uniformly across severity — there is no public
clock that depends on a fast, contestable severity call under time pressure.
Most fixes ship well inside it; severity still drives internal prioritization,
just not which published deadline applies.

**CRITICAL** (for internal prioritization and the advance-notice trigger, not
a separate published deadline — High and Critical share the same published
treatment above): remote, unauthenticated compromise of stored secret values,
or of the authentication boundary itself, requiring no valid credential of any
kind and no prior account state. See ADR-104 for the full definition and
worked examples of severe findings that do *not* clear this bar (and are
still HIGH, with the same published commitment).

This is a current operating commitment, not a CRA-declared support period —
see "Supported versions" above for that distinct, separate axis.

## Security documentation

| Document | Covers |
|---|---|
| [`security/threat-model.md`](security/threat-model.md) | Assets, trust boundaries, STRIDE analysis, and stated residual risks — including open items, not only mitigated ones. |
| [`security/architecture.md`](security/architecture.md) | How encryption, authentication, authorization, transport, process hardening, and air-gap operation actually work, with citations. |
| [`security/hardening-guide.md`](security/hardening-guide.md) | A production configuration checklist with the exact config keys, verified against `internal/config`. |
| [`security/testing.md`](security/testing.md) | CI gates, the fuzzing program, differential/property testing, and the machine-checked coverage ledgers. |
| [`compliance/README.md`](compliance/README.md) | Regulatory control mappings (NIS2, DORA, ISO 27001, ENS, SOC 2) built on top of the above. |
| [`compliance/SECURITY-FAQ.md`](compliance/SECURITY-FAQ.md) | The questions a buyer's security team typically asks during a vendor review. |
| [`compliance/SECURITY-VERIFICATION.md`](compliance/SECURITY-VERIFICATION.md) | The security audits performed to date, issues found and fixed, and the standing CI gates. |
| [`compliance/AUDIT-LOG-PROVISIONS.md`](compliance/AUDIT-LOG-PROVISIONS.md) / [`compliance/OFFLINE-AUDIT-VERIFICATION.md`](compliance/OFFLINE-AUDIT-VERIFICATION.md) | What's logged, how, and how to independently verify the audit tamper-evidence chain without trusting the running server. |

## Repository-level protections

GitHub-native secret scanning and push protection, Dependabot security
updates, and private vulnerability reporting are all enabled on this
repository. Branch protection requires 11 status checks (static analysis,
`govulncheck`, fuzz coverage, license compliance, DCO, and more — see
[`security/testing.md`](security/testing.md)) with no bypass, including for
maintainers.
