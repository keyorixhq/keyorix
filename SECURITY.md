# Security Policy

Keyorix is a secrets manager. We hold ourselves to the standard we ask you to trust
us with: every control described here is verifiable in this repository's CI
configuration and release artifacts.

## Supported Versions

| Version | Supported |
|---|---|
| Latest release | ✅ Security fixes |
| Older releases | ❌ Upgrade to latest |

Keyorix is pre-1.0. A formal backport policy for previous minor versions (relevant
for air-gapped deployments with slow upgrade cadences) will be published with the
1.0 release; commercial licence tiers will include extended backport windows.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

- Email: **security@keyorix.com**
- Or use GitHub's private vulnerability reporting on this repository

We acknowledge within **48 hours** and provide an initial assessment within **7 days**.
Please include: a description, reproduction steps, and the affected version
(`keyorix --version` / `keyorix-server --version`).

We follow coordinated disclosure: we'll agree a disclosure timeline with you,
credit you in the advisory unless you prefer otherwise, and publish a fix and
advisory together. As an EU vendor we operate under the EU Cyber Resilience Act
reporting regime for actively exploited vulnerabilities.

## Threat Model (summary)

Keyorix server runs **entirely within your perimeter**:

- No telemetry, no usage metering, no "phone home" — ever. Air-gapped operation
  is a first-class deployment model, not a degraded mode.
- All secret values encrypted at rest with AES-256-GCM (authenticated encryption,
  AAD-bound to secret identity). Envelope encryption: the data key is wrapped by a
  key derived from an operator passphrase (PBKDF2-SHA256, 600k iterations); no
  plaintext key material is ever written to disk.
- Session tokens, API tokens, and client secrets are encrypted at rest.
- Every secret access and every administrative action is written to an append-only
  audit log in your database.
- RBAC is enforced at the API level, not the UI.

What Keyorix never does: open outbound connections to us, embed third-party
analytics, or require internet access for any cryptographic operation.

A full STRIDE threat model is maintained internally and shared with customers and
prospects under evaluation — ask via hello@keyorix.com.

## Verifying a Release

Every release ships with `checksums.txt`:

```bash
sha256sum --check --ignore-missing checksums.txt
```

Release binaries are built with `-trimpath` and `CGO_ENABLED=0` from the tagged
commit. Cryptographic release signing (Sigstore/cosign) and SLSA build provenance
are being rolled out — this section will be updated with verification commands
when they ship. Until then, download releases only from
`github.com/keyorixhq/keyorix/releases` over HTTPS and verify checksums.

## Secure Development

- Pre-commit gates: `gofmt`, `go vet`, `go build`, `gosec` (MEDIUM+ severity)
- CI gates on every push and pull request: `go vet`, race-enabled tests,
  `govulncheck`, `gosec` (pinned version), `golangci-lint` (errcheck, staticcheck,
  unused, and more), `gitleaks` full-history secret scan
- Any change to the encryption layer requires a written Architecture Decision
  Record before implementation
- External contributions require a signed CLA and maintainer review

## Security-Relevant Configuration

- `KEYORIX_MASTER_PASSWORD` is the root credential — inject it via systemd
  credentials/`EnvironmentFile` (0600) or a Kubernetes Secret, never a config file.
- Run `keyorix-server` as a non-root service user.
- TLS is required in production; the CLI `--insecure` flag is for local
  development only.
