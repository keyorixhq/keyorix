### Security
- **Vault, Azure Key Vault and Kubernetes endpoint validation errors no longer echo the configured URL.** `connect` (Vault `address`), `azurekms` (`kms_key_id` and the vault origin) and `dynamic` (Kubernetes `api_server`) named the full value, and the wrapped `url.Parse` error quotes the raw input, so userinfo, a `?token=` query or a password in a malformed port could reach a startup error. The Vault connector's non-200 read error and its link-local refusal (also used for Azure Key Vault) printed the raw `address` into the server log the same way, and the Vault token lookup (run at boot), mount-info lookup and secret read, plus the Kubernetes TokenRequest and bound-Secret calls, passed on net/http's request error, which quotes the full request URL with only a password masked. They now name scheme and host only (`netutil.RedactURLHost`, `netutil.RedactErrorURLs`). This clears the ten `urlleakguard` reports left by #3835.

### Fixed
- **The OpenAPI description, the gRPC comment and the recovery-options doc for the audit-checkpoint and evidence-signing keys say KEK-derived.** The proto, `openapi.yaml`, the generated gRPC and web types and `docs/design/recovery-options.md` still called these keys DEK-derived. The OpenAPI text also said a DEK rotation changes the key; only a KEK change does: a KEK rotation (`rotate-kek`) or a KEK-provider migration.

### Testing
- **A wording guard fails when a non-ADR doc or a Go comment calls a checkpoint or evidence key DEK-derived.** `TestNoDEKDerivedWordingForKEKDerivedKeys` (`internal/docsdrift`) is report-only until its first green nightly on main.

### Internal
- **Guard inputs.** `scripts/ci/guard-inputs.tsv` maps the new wording guard to the paths it reads.
