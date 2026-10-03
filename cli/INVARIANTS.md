# cli invariants

Read this before changing anything in `cli/` (its own Go module, split from the main module by
ADR-108 "cli-server-split"). The CLI is a pure HTTP client of the real server — it has zero
capability to touch storage/core directly, which structurally closes an entire historical bug
class (see INV-CLI-01). Do not reintroduce a dependency that would reopen it.

Format: `INV-CLI-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## Module boundary (ADR-108 Decision A)

- **INV-CLI-01** The `cli` module's dependency graph never includes `internal/core`,
  `internal/storage`, `internal/config`, `server/`, or any cloud SDK
  (`aws-sdk-go`/`aws-sdk-go-v2`, `azure-sdk-for-go`, `cloud.google.com/go`,
  `hashicorp/vault/api`) — checked via real `go list -deps ./...` (catches indirect imports
  too), not a source grep. This is what makes the historical actor-ID/SoD-bypass bug class
  (hardcoded actor ID 1 in `share create/update/revoke`, SoD/last-admin bypass via direct
  storage writes in the old `internal/cli/rbac/group_role.go`) STRUCTURALLY closed, not merely
  fixed-in-place: the new CLI always sends the authenticated caller's own session/token to the
  server, which derives the real actor server-side — there is no client-side actor-ID field to
  hardcode, because there is no client-side write path to storage at all. Why: ADR-108
  Decision A; security-closures rows `CLI-AUTH-001`, `cli-connect-002`, `cli-connect-004`,
  `cli-rbac-001`, `cli-rbac-002`, `cli-secret-001` (all "SURFACE REMOVED" — the old
  `internal/cli` tree was deleted entirely, confirmed gone: no directory, no import anywhere
  in the repo). Guard: `cli/internal/depguard/depguard_test.go:TestNoServerOrCloudSDKDependencies`
  (live-verified in this research pass: `cli`'s actual main-module dependency graph is exactly
  `pkg/bundleverify`, `pkg/licenseverify`, `pkg/trust` — nothing else).
- **INV-CLI-02** The old `isLoopbackHost`-string-prefix SSRF bug class (`127.evil.com`
  defeating a naive check) no longer applies — no code in `cli/` resolves or validates an
  arbitrary connector-controlled target host at all; the module only ever talks to the one
  operator-configured server URL. Not a gap to guard — confirmed structurally absent.
- **INV-CLI-03** `depguard`'s `forbiddenPrefixes` list does not name `internal/crypto` or
  `internal/encryption` — not a live violation today (confirmed via `go list -deps`), but the
  test's own stated intent ("no server/core/storage") is broader than its literal prefix list,
  and a future direct import of e.g. `internal/crypto`'s base passphrase/PBKDF2 code (no SDK
  dependency itself, only its `awskms`/etc. subpackages pull one in) would slip through
  unnoticed. UNGUARDED (#issue: add `internal/crypto` and `internal/encryption` to
  `forbiddenPrefixes` defensively).

## Authentication / credential storage

- **INV-CLI-04** The CLI authenticates to the server via Bearer token only — no cookie
  concept exists anywhere in `cli/`. Guard: `cli/cmd/client.go:newAPIClient` (lines ~57-66).
- **INV-CLI-05** `NewHardenedHTTPClient` wraps every API call with a timeout, a response-size
  cap, and redirect refusal — ported explicitly from the old CLI's hardening (#1521/#1606), not
  reinvented. Guard: `cli/internal/apiclient/hardened_client_test.go`.
- **INV-CLI-06** No AST/completeness sweep confirms every mutating subcommand routes through
  `newAPIClient` rather than rolling its own HTTP call — verified by hand in this research pass
  (zero `go/ast`/`go/parser`/`go/packages` usage anywhere in `cli/`, zero raw
  `http.NewRequest`/`http.Client{}`/`http.Get`/`http.Post` outside `client.go` itself). The
  invariant holds today by inspection only. UNGUARDED (#issue: add a structural sweep analogous
  to `internal/core`'s atomicity guards, since `go/ast` IS available to this module unlike a
  cloud SDK).
- **INV-CLI-07** Local credentials (`credstore.FileStore`) are stored in a plaintext YAML file
  at `os.UserConfigDir()/keyorix/credentials.yaml`, always mode 0600 via an explicit `Chmod`
  after open (not relying on `O_CREATE`'s mode, since `O_TRUNC` preserves a pre-existing file's
  mode); `Load` refuses to read if permissions are wider than 0600 or if the final path
  component is a symlink. No OS-keychain backend exists yet — explicitly deferred, not a gap.
  Guard: `cli/internal/credstore/file_test.go` (`TestFileStore_SaveWritesMode0600`,
  `_SaveFixesPreExistingWidePermissions`, `_LoadRefusesWiderPermissions`,
  `_LoadRefusesGroupReadablePermissions`, `_LoadRefusesSymlink`); `file_fuzz_test.go`.
- **INV-CLI-08** `cli/internal/securefiles` is a deliberate ported trim of the main module's
  `internal/securefiles` (the CLI module CANNOT import that package — forbidden by depguard),
  with the identical TOCTOU-safe guarantee: `SecureOpenBeneath` walks path components via
  `unix.Openat` with `O_NOFOLLOW|O_DIRECTORY` per intermediate component, refusing a symlink at
  ANY path level, not just the leaf. Guard: `securefiles_test.go`, `write_test.go`,
  `securefiles_fuzz_test.go`.

## Version skew (ADR-108 Decision 3)

- **INV-CLI-09** `minimum_cli_version` is a hard policy floor (different major, or below floor
  → `Refuse: true`); `api_version` is a soft epoch-drift signal (server ahead → "upgrade
  available" warning; CLI ahead → "server too old" warning). Checked on EVERY command via
  `apiClientWithSkewCheck`, not just `login`/`status`. Guard: `cli/internal/skew/skew_test.go`
  (26 cases per ADR-108's own conformance table), `skew_fuzz_test.go`.
- **INV-CLI-10** The old-CLI config migration (`cli/internal/migrate`) copies only a server URL
  from either legacy config file, never the old API key — a different credential kind;
  the operator re-authenticates either way, never silently inheriting a stale credential. Guard:
  `migrate_test.go`.

## Secret injection into child processes — highest-priority gap

- **INV-CLI-11** `keyorix run` filters dangerous environment-variable names
  (`dangerousEnvPrefixes`: `LD_`, `DYLD_`, `NODE_`, `PYTHON`, `PERL5`, `BASH_`, `GCONV_`,
  `MALLOC_`; `dangerousEnvExact`: `IFS`, `ENV`, `HOME`, `SHELL`, `PATH`, `RUBYOPT`,
  `GIT_SSH_COMMAND`) before injecting secrets into a child process's environment — a secret
  named `LD_PRELOAD` must never reach the child unfiltered (code execution against anyone
  running `keyorix run`). Why: CLI-RUN-001/#1816 — this is the exact bug class the old CLI had.
  An explicit `--var NAME=secret-ref` mapping onto one of these names is a deliberate operator
  choice and is allowed (with a warning), unlike `--derive-names`. Guard:
  `cli/cmd/run_env_filter_test.go` (`TestIsDangerousEnvKey_*`, `TestDropDangerousEnvKeys_*`
  incl. `_RedProof`, `TestResolveChildEnvVars_DeriveNames_DropsReservedNames`,
  `TestResolveChildEnvVars_VarMapping_AllowsReservedNameExplicitly`) (#2527).
- **INV-CLI-12** The old embedded/local-mode secret-fetch path for `run` (which had zero auth
  check and zero audit event) was deliberately NOT ported to the new CLI — `run` is REST-only
  now. Not a gap — a documented security fix by omission.

## Fuzz coverage

- **INV-CLI-13** `apiError` (API error formatting) never panics on any `(statusCode, body)`
  pair, and the resulting error text never carries a raw control rune through to the terminal —
  closes a terminal-injection gap, since `apiError` does not route through
  `cliout.SanitizeForTerminal` the way other free text does. Guard:
  `cli/cmd/client_fuzz_test.go:FuzzApiError`.
- Other fuzz targets with their own narrower oracles: `secret_import_parsers_fuzz_test.go`,
  `cliout/table_fuzz_test.go`, `credstore/file_fuzz_test.go`, `securefiles/securefiles_fuzz_test.go`,
  `skew/skew_fuzz_test.go`.

## Ledger gap

- `docs/adr-conformance-enforced.tsv` has zero rows mentioning `cli` at all — ADR-108's own
  conformance table (inside the ADR doc, dated 2026-09-28) is the only place these properties
  are tracked today; nothing has been transcribed into the enforced-properties ledger.
