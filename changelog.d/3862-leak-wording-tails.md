### Security
- **Vault, Azure Key Vault and Kubernetes endpoint validation errors no longer echo the configured URL.** `connect` (Vault `address`), `azurekms` (`kms_key_id` and the vault origin) and `dynamic` (Kubernetes `api_server`) named the full value, and the wrapped `url.Parse` error quotes the raw input, so userinfo, a `?token=` query or a password in a malformed port could reach a startup error. They now name scheme and host only (`netutil.RedactURLHost`, `netutil.RedactErrorURLs`). This clears the ten `urlleakguard` reports left by #3835.

### Fixed
- **The OpenAPI description, the gRPC comment and the Go comments for the audit-checkpoint and evidence-signing keys say KEK-derived.** The proto, `openapi.yaml`, the generated gRPC and web types and several comments still called these keys DEK-derived. The OpenAPI text also said a DEK rotation changes the key; only a KEK-provider migration does (ADR-029, since #502).

### Testing
- **A wording guard fails when a non-ADR doc or a Go comment calls a checkpoint or evidence key DEK-derived.** `TestNoDEKDerivedWordingForKEKDerivedKeys` (`internal/docsdrift`) is report-only until its first green nightly on main.

### Internal
- **Web dependency audit.** `follow-redirects` (pulled in by axios) is overridden to `>=1.16.2` (GHSA-mrwp-f3q8-3g9p) so `pnpm audit --prod` passes again, and `scripts/ci/guard-inputs.tsv` maps the new wording guard to the paths it reads.
