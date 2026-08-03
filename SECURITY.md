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

Every release also ships a **CycloneDX SBOM** per binary
(`keyorix_sbom.cdx.json`, `keyorix-server_sbom.cdx.json`) — a full dependency and
licence inventory, the component list needed to assess CVE exposure under the EU
CRA. Both SBOMs are covered by `checksums.txt`.

Release binaries are built with `-trimpath` and `CGO_ENABLED=0` from the tagged
commit. `checksums.txt` and every container image are keylessly signed with
[Sigstore/cosign](https://www.sigstore.dev/) via GitHub's OIDC token — no
long-lived signing key exists to leak. Verify with `cosign` installed:

```bash
# checksums.txt (release binaries)
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/keyorixhq/keyorix/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# container images (also carries an SBOM + SLSA build provenance attestation)
cosign verify \
  --certificate-identity-regexp 'https://github.com/keyorixhq/keyorix/\.github/workflows/docker-publish\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/keyorixhq/keyorix-server:<tag>
```

Download releases only from `github.com/keyorixhq/keyorix/releases` over HTTPS.

## Secure Development

- Pre-commit gates: `gofmt`, `go vet`, `go build`, `gosec` (MEDIUM+ severity)
- CI gates on every push and pull request (11+ required checks, see
  [CONTRIBUTING.md](CONTRIBUTING.md) for the full list): `go vet`, race-enabled
  tests, `govulncheck`, `gosec` (pinned version), `golangci-lint`, `gitleaks`
  secret scan (scoped to the PR's own commit history), `CodeQL` (dataflow/taint
  analysis, both Go modules), Helm chart schema validation (`kubeconform`) and
  security-policy scanning (`checkov` — pod security context, RBAC-escalation
  checks), Go dependency license compliance (rejects any dependency outside an
  explicit permissive-license allowlist), and DCO sign-off verification
- Continuous fuzzing: native Go fuzz targets (`go test -fuzz`) at the
  codebase's highest-risk parsing/escaping boundaries (Shamir secret-share
  reconstruction, JWT/OIDC verification, rotation-credential SQL escaping and
  ref interpolation, secret-template parsing) run for hours at a time on
  dedicated infrastructure, well beyond what a CI job's budget allows — see
  [`scripts/fuzzing/README.md`](scripts/fuzzing/README.md)
- [CODEOWNERS](.github/CODEOWNERS) requires review on cryptography, auth/RBAC,
  middleware, database migrations, the CI/CD pipeline itself, and this policy
- GitHub-native repository security: secret scanning, push protection (blocks
  a commit containing a detected secret before it lands), Dependabot security
  updates, and private vulnerability reporting are all enabled
- Any change to the encryption layer requires a written Architecture Decision
  Record before implementation
- External contributions require DCO sign-off (`git commit -s` — see
  [CONTRIBUTING.md](CONTRIBUTING.md)) and maintainer review. Branch protection
  on `main` requires every required CI check to pass (enforced for maintainers
  too, no bypass) before a PR can merge.

## Security-Relevant Configuration

- `KEYORIX_MASTER_PASSWORD` is the root credential — inject it via systemd
  credentials/`EnvironmentFile` (0600) or a Kubernetes Secret, never a config file.
- Run `keyorix-server` as a non-root service user.
- TLS is required in production; the CLI `--insecure` flag is for local
  development only.
