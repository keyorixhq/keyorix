# docs/configuration.d/ — one file per new config key

**Document a NEW config key here, not in `docs/CONFIGURATION.md`.** Each `*.md` file in this
directory documents exactly one key, with the text you would otherwise have appended to
`docs/CONFIGURATION.md`: what the key does, its type and default, and when to change it. Name the file
`<the key with dots replaced by __>.md` (e.g. `storage__database__fdatasync.md` for
`storage.database.fdatasync`). The text must name the key the way the reference page does: its full
dotted path (`storage.database.fdatasync`), a ` ```yaml ` block that nests it, or a table row under a
heading that names its parent in backticks. Existing text in `docs/CONFIGURATION.md` stays where it
is; nothing is migrated.

Why: `docs/CONFIGURATION.md` was among the most conflicted files in a 14-day look at merged PRs, and a
PR that adds a key goes red on `TestEveryConfigKeyIsDocumented` when a rebase moves the text it
appended to. A new file cannot conflict with anyone else's new file.

Reader: `go test -run 'TestEveryConfigKeyIsDocumented|TestConfigFragment' ./internal/docsdrift/`
reads `docs/CONFIGURATION.md`, the self-hosting guide, the quick start PLUS every `*.md` here
(dual-read). A key counts as documented if it appears in any of them. The other readers of
`docs/CONFIGURATION.md` read the fragments too: `TestDocsConfigKeysExist` (a yaml block or key table
here that names a key the config struct does not have fails), `TestInsecureRegistryEntriesAreDocumented`,
the env-var and command checks in `internal/docsdrift` and `server/admin`. It fails on a fragment
whose name is not `<key with dots as __>.md`, whose key is not a config key, that is empty or never
names its key (it documents nothing), and on a key already documented in the flat documents — one
place per key, as the ledger readers do for a key that appears twice when one copy is a fragment.
This `README.md` is not a fragment.

Not covered: the renamed-settings table in `docs/CONFIGURATION.md` (`TestConfigurationDoc_ListsEveryDeprecatedAlias`,
`TestConfigurationDoc_AliasTableHasNoStaleRows`, `TestDocs_ConfigurationListsEveryDeprecatedAlias`)
lists renames, not new keys, and stays a flat table in `docs/CONFIGURATION.md`.

## Folding (dedicated documentation PRs only)

A feature or fix PR never edits `docs/CONFIGURATION.md`. A documentation PR on a branch whose
name starts with docs/fold- or docs/consolidate- folds the fragments in with one command, then runs the
docs guards:

```
scripts/docs/fold-fragments.sh            # append each fragment into its section, delete the file
go test ./internal/docsdrift/
```

`--dry-run` shows where each fragment would go; `--check` exits 1 if one cannot be placed. A
fragment goes at the end of the first section that matches: a heading naming the key's parent in
backticks (longest parent first), else the `## <heading>` that `scripts/docs/fold-fragments.map`
gives for the key's prefix, else `## <first segment of the key>`. A key the script cannot place
fails with a message: add a rule to the map file. Relative links (`../X.md`) lose one `../` on the
way up. The script also folds `docs/upgrading.d/` (see its `README.md`).
