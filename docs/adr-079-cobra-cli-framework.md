# ADR-079: Cobra as the CLI framework

## Status

Accepted, as-built. Backfill ADR — Cobra's adoption predates the ADR series.
Recorded now per the M2 "ADR backfill" backlog item.

## Context

`keyorix` (the CLI binary) is a large, growing command surface: 37 command-group
subdirectories under `internal/cli/` (accessreview, audit, auth, billing,
bundle, compliance, connect, dynamic, encryption, group, invite, license, machine,
migrate, pat, project, rbac, request, risk, rotation, secret, share, sod, system,
trust, usage, user, and more), roughly 306 individual `cobra.Command` definitions
across 169 files. It needs to support:

- **Nested command groups** (`keyorix secret get`, `keyorix rotation plan
  --all-projects`, `keyorix machine token issue`) rather than a flat list of
  top-level flags.
- **Two structurally different execution modes per command** — "local"/embedded
  (talk directly to a local SQLite/Postgres-backed core service, no server running)
  and "remote"/client (talk to a running Keyorix server over HTTP), selected by
  `internal/cli/modes.go`'s `detectMode()`. Every command needs to work in both
  without duplicating its logic.
- **Per-command flags that still need consistent names and behavior** across the
  whole surface (`--project`, `--by <admin-email>` for audited-actor commands with
  no session, `--format`/`--json` for structured output) even though, as built,
  these are not wired through Cobra's `PersistentFlags()` inheritance — each leaf
  command declares its own `Flags().StringVar(...)` and the consistency comes from
  convention plus shared resolver helpers (`common.ResolveProject`,
  `common.ResolveRemote`), not from the framework enforcing it structurally.

## Decision

Adopted **`github.com/spf13/cobra`** (currently v1.10.2) as the CLI framework.
`internal/cli/main.go`'s `init()` registers roughly 30 top-level command groups
onto `rootCmd`; each group's own package wires its leaf subcommands (e.g.
`internal/cli/secret/secret.go` wires 10 subcommands under `secret`). Cobra's
nested-command-tree model maps directly onto the CLI's natural
noun-then-verb shape (`keyorix <resource> <action>`) without a hand-rolled
subcommand dispatcher.

**Viper was deliberately not adopted alongside Cobra**, despite being Cobra's most
common config-binding companion. Config binding is hand-rolled instead:
`internal/config` (`config.Load`/`config.LoadConfig`) for the server/embedded-mode
config and `internal/cli/config` (`cliconfig.LoadCLIConfig`) for the CLI's own
`~/.keyorix/cli.yaml`. ADR-049 records this explicitly for the storage-factory path
("No `KEYORIX_STORAGE_TYPE` or Viper `AutomaticEnv` is introduced") — this ADR
generalizes that as the standing rule: environment-variable and config-file
resolution stays explicit and grep-able in this codebase's own resolver functions,
not implicit through Viper's automatic env-binding, which would make it harder to
audit exactly which env vars a given command reads.

**Local/remote dual-mode is not implemented via Cobra flag inheritance.** As built,
no production command uses `PersistentFlags()` (confirmed absent from
`internal/cli` outside tests) — `internal/cli/modes.go`'s `CLIMode` enum
(`EmbeddedMode`/`ClientMode`) and per-command calls into
`common.ResolveProject()`/`common.ResolveRemote()` carry the mode-resolution logic
instead. Cobra's contribution here is structural (a command tree that both modes'
`RunE` functions can share) rather than Cobra-specific plumbing (inherited flags,
built-in config binding) — the framework provides the tree, the codebase provides
its own resolution conventions on top.

**Rejected alternatives, implicitly rather than via formal comparison** (no
contemporaneous doc weighing these exists): `urfave/cli` and `kingpin` offer
similar nested-command support but smaller ecosystems and less precedent in
comparable Go CLI tools (`kubectl`, `helm`, `docker` — all Cobra-based, a relevant
signal for a CLI whose users are the same operator audience); the stdlib `flag`
package alone would mean hand-rolling subcommand dispatch, help text, and usage
generation for 300+ commands — a maintenance burden Cobra removes essentially for
free.

## Consequences

- **Positive.** A 37-group, 300+-command surface stays navigable — Cobra's built-in
  help/usage generation means every command gets `--help` output for free, and the
  nested tree keeps `internal/cli/main.go`'s registration simple even as the
  surface has grown roughly 3x since the CLI's early days (project/environment
  commands only, per the backlog's ADR-016/017 entries) to today's scope (billing,
  compliance, dynamic secrets, machine identities, rotation planning, and more).
- **Negative / accepted tradeoff.** Because `PersistentFlags()` was never adopted,
  cross-cutting flags like `--project`/`--by` are declared per-leaf-command rather
  than inherited once at a group root — every new command author has to know to
  wire the shared resolver helpers themselves rather than getting them free from
  the command tree. This is a deliberate tradeoff already implicit in the
  as-built code (not newly decided here), and not revisited: retrofitting
  `PersistentFlags()` across 300+ existing commands would be a large,
  purely-mechanical change for a consistency gain that hasn't caused a reported
  bug.
- Not currently used: Cobra's completion (`GenBashCompletion` etc.) and
  Markdown-doc-generation (`GenMarkdownTree`) helpers are available but unwired —
  `keyorix completion` presumably works via Cobra's own default subcommand, but
  there's no custom completion or generated-docs tooling in this repo today. Left
  as a genuinely open, low-priority follow-up rather than claimed as done here.
