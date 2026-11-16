# internal/restorejournal invariants

Read this before changing anything in `internal/restorejournal` — the on-disk journal
`keyorix-server admin restore` keeps while it installs a restore whose halves live on the
filesystem and in the database. While the journal exists the server refuses to start
(`RefuseIfPresent`) and `admin restore --recover` finishes or undoes the restore. See the
package doc comment in `journal.go`.

Format: `INV-RESTOREJOURNAL-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-RESTOREJOURNAL-<kebab-slug>.md` (one per file), not
appended here — see `docs/invariants-fragments.md`.
