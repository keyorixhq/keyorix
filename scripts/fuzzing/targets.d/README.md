# scripts/fuzzing/targets.d/ — one fuzz target per file

Each file is named `<pkg-slug>__<FuzzName>.conf`, where `<pkg-slug>` is the
target's Go package path with every `/` replaced by `-` (e.g.
`internal/core/rules` → `internal-core-rules`). File content is the same
`<go-package-path>|<FuzzFuncName>|<go-test-fuzztime>` line this repo's fuzz
targets have always used, optionally preceded by `#`-comment lines explaining
why the target exists and how its duration was chosen.

## Adding a target

Add a new `<pkg-slug>__<FuzzName>.conf` file here (copy an existing one for the
format), then run:

```
scripts/fuzzing/gen-targets-conf.sh
```

to regenerate `scripts/fuzzing/targets.conf`, and commit both. CI
(`fuzz-targets` job) fails if you forget the regenerate step, or if the new
`func FuzzXxx` doesn't actually exist in the tree.

**This is the whole point of the split**: a new target is a new file, so two
PRs adding two different targets never touch the same line and never conflict.
Before this, every fuzz-target PR appended a line to one shared
`targets.conf`, and any two such PRs open at once were a guaranteed merge
conflict — this directory replaces that with one-file-per-target.

## Why targets.conf still exists

`scripts/fuzzing/targets.conf` is GENERATED from this directory
(`gen-targets-conf.sh`) and committed alongside it, purely because the
external `keyorixhq/fuzz-harness` rig repo's runner still reads that single
flat file to discover what to fuzz. See "HANDOFF: fuzz-harness" below for the
follow-up that removes this generated file entirely once the rig points at
`targets.d/` directly.

## HANDOFF: fuzz-harness (external repo, not touched by this PR)

`keyorixhq/fuzz-harness`'s runner (referenced from this repo's own
`scripts/fuzzing/README.md`) reads `scripts/fuzzing/targets.conf` in the
target Keyorix checkout to discover what to fuzz. Once this PR merges, that
repo should be updated to read `scripts/fuzzing/targets.d/*.conf` directly
instead (concatenate, `grep -vE '^[[:space:]]*(#|$)'`, `awk -F'|'`, same as
`scripts/fuzzing/gen-targets-conf.sh` does) — that removes the one remaining
reason `targets.conf` needs to exist as a committed, generated artifact at
all, and lets it be deleted. Until that lands, `targets.conf` must keep being
regenerated and committed by every PR that touches `targets.d/` (CI enforces
this via `gen-targets-conf.sh --check`), so the rig keeps working unmodified.

Exact steps for whoever picks this up in `fuzz-harness`:
1. In the runner's target-discovery step, replace reading
   `<checkout>/scripts/fuzzing/targets.conf` with concatenating
   `<checkout>/scripts/fuzzing/targets.d/*.conf` (sorted glob order is fine;
   duplicate `pkg|Fuzz` pairs cannot occur — each target owns exactly one
   file).
2. Confirm the parse step already strips `#`-comment and blank lines (it must,
   since targets.conf itself has always had both) — no change needed there.
3. Once the runner is updated and deployed, open a follow-up PR against this
   repo (Keyorix) deleting `scripts/fuzzing/targets.conf`,
   `scripts/fuzzing/gen-targets-conf.sh`, and the `fuzz-targets` job's
   "Verify targets.conf is generated from targets.d/*.conf" step — at that
   point `targets.d/*.conf` becomes the only fuzz-target file in the repo, and
   the `fuzz-targets` job's tree-vs-declared drift check should read from
   `targets.d/*.conf` (it already does, see `ci.yml`).

## Tier / batch context (was section-banner comments in the old single file)

The old `targets.conf` grouped targets under a few section banners; those
targets' own per-file comments preserve the immediately-adjacent rationale,
but the banner framing text itself is reproduced here for context:

- **Tier-1** (`#1889`, added 2026-09-15): PAT scope/CIDR decode, SCIM token
  strength, secret ACL/ref parsing, bundle key PEM parsing, encryption
  envelope deserialize, and the SAML response parse path — a
  security-weighted initial guess, re-tuned once saturation data exists.
- **Tier-2** (`fuzz/tier2-jwk-mcp`): data/inspection-selected walled parsers —
  JWKS key parsing, MCP stdio JSON-RPC, and the SAML XSW structural family —
  targets not reached by the static-resolver OIDC harness or byte-level SAML
  parse target.
- **Behind-the-wall soak** (`fuzz/behind-the-wall-batch`): pours mutation
  *past* a signature/JSON wall by signing/encoding each iteration's fuzzed
  content with a trusted key, so the code behind the wall (claim semantics,
  assertion extraction, attestation formats) actually gets exercised instead
  of dying at the wall on every run.

Per-target rationale (duration, what it catches, real findings) lives in each
target's own file in this directory, not in this README.
