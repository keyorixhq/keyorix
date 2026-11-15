# internal/rotation invariants

Read this before changing anything in `internal/rotation`. This package executes credential
rotations against cloud providers (AWS IAM, Azure AD app secrets). Outbound HTTP to a provider
must be hardened like every other outbound client in the repo, and a `ref` interpolated into a
provider URL path must be validated so it cannot path-traverse past its allowlist.

Format: `INV-ROTATION-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-ROTATION-<slug>.md`, one per file.
