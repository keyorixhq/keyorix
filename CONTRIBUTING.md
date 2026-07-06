# Contributing to Keyorix

Thanks for considering a contribution.

## Before you start

- **Security issues**: do not open a public issue or PR. See
  [SECURITY.md](SECURITY.md) for the private disclosure process.
- **Bigger changes**: open an issue first to discuss the approach, especially
  for anything touching encryption/key management (see
  [SECURITY.md](SECURITY.md) — those changes need a written ADR before
  implementation) or authentication/authorization.
- **License**: everything in this repository is AGPL-3.0 (see
  [LICENSE](LICENSE) / [LICENSING.md](LICENSING.md)). Your contribution will
  be under the same license.

## Developer Certificate of Origin (DCO)

Every commit must be signed off, certifying you wrote it (or otherwise have
the right to submit it) under the
[Developer Certificate of Origin](https://developercertificate.org/):

```
git commit -s -m "your commit message"
```

This adds a `Signed-off-by: Your Name <you@example.com>` trailer to the
commit, matching your git author identity — nothing more. A CI check
(`.github/workflows/dco.yml`) verifies every commit in a PR has one; PRs
without it won't pass CI. If you forgot:

```
git commit --amend -s --no-edit                              # last commit only
git rebase --exec 'git commit --amend --no-edit -s' <base>    # every commit since <base>
```

## Making a change

1. Fork (or branch, if you have write access) and make your change.
2. Run the checks locally before opening a PR — CI enforces all of these:
   ```
   make ci          # go vet + go test -race + gosec + govulncheck + build
   golangci-lint run ./...
   ```
   For a change touching `operator/` (its own Go module):
   ```
   cd operator && GOWORK=off go vet ./... && GOWORK=off go test ./...
   ```
3. Add a test that fails without your change and passes with it — this is a
   hard requirement for anything security-relevant (see
   [docs/compliance/SECURITY-VERIFICATION.md](docs/compliance/SECURITY-VERIFICATION.md)
   for what that verification standard looks like in practice).
4. Open a PR against `main`. CI must pass in full before it can merge
   (branch protection enforces this — there's no bypass, including for
   maintainers).

## What CI checks

11 required checks gate every merge to `main` (branch protection, no bypass):

- `go vet`, `go build`, `go test -race` (full suite)
- `gosec` (medium+ severity) and `golangci-lint`
- `govulncheck` against known vulnerabilities in dependencies
- `gitleaks` (the PR's own commit history, not the whole repo's other branches)
- `CodeQL` (dataflow/taint analysis, both Go modules)
- Helm chart lint + schema validation (`kubeconform`) for all three charts
- `checkov` — Helm chart security-policy scanning (pod security context,
  RBAC-escalation checks), distinct from `kubeconform`'s schema-only validation
- Go dependency license compliance (`go-licenses`) — rejects any dependency
  outside an explicit permissive-license allowlist, both Go modules
- Fuzz-target staleness — `scripts/fuzzing/targets.conf` (the self-hosted
  continuous-fuzzing rig's config) must exactly match every real `func FuzzXxx`
  in the tree; adding a fuzz target without declaring it here fails CI
- DCO sign-off (`git commit -s` on every commit — see above)

## Code style

`gofmt` and `golangci-lint` are the source of truth — there's no separate
style guide to read. If the linter's happy, the style's right.
