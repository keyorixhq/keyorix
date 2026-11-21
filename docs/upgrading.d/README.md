# docs/upgrading.d/ — one file per upgrade note

**Put the upgrade note for your PR here, not in `docs/UPGRADING.md`.** Each `*.md` file in this
directory is one note: what an operator must do (or will see) when upgrading to the release that
carries the change, with the old and new behaviour and the exact command or setting. Name the file
`<slug>.md` (lower case, e.g. `fdatasync-default.md`), start it with an unnumbered `## <title>`
heading, and do not give it a section number: `docs/UPGRADING.md` numbers its sections (6a ... 6z,
6aa), and the number is assigned when the note is folded in. Existing text in `docs/UPGRADING.md`
stays where it is; nothing is migrated.

Why: `docs/UPGRADING.md` was among the most conflicted files in a 14-day look at merged PRs, because
every PR with a breaking or operator-visible change appended a section to it (`docs/VERSIONING.md`
requires one for every breaking change). A new file cannot conflict with anyone else's new file.

Folding in: only a dedicated documentation PR (branch name starting docs/fold- or docs/consolidate-) edits
`docs/UPGRADING.md`, and it does so with one command, followed by the docs guards:

```
scripts/docs/fold-fragments.sh            # number, insert and delete each fragment
go test ./internal/docsdrift/
```

For each fragment, in file-name order, the script takes the next free section number (the id after
the highest `6<letters>`: `6z`, `6za`, `6zb`, ...), puts the text under that numbered heading after the
last `## 6...` section, rewrites its `../` links, and deletes the fragment. `--dry-run` shows the
numbers it would assign and `--check` exits 1 if a fragment cannot be placed (for example one that
does not start with an unnumbered `## <title>`). It does not rewrite cross-references to other
sections inside your text: read the folded result once. A fragment that is still here after the
release it names has shipped is a defect.

Reader: `go test -run 'TestUpgradingFragmentsAreWellFormed' ./internal/docsdrift/` fails on a fragment with a name
that is not a lower-case slug, an empty one, or one with a numbered `## 6x` heading.
`TestUpgradingSectionReferencesResolve` already walks every `.md` under `docs/`, so a `§6q`
reference in a fragment must name a heading that exists in `docs/UPGRADING.md`.
`TestDockerDocsAdminCommandsAreRunnable` (`server/admin`) reads the fragments for
`docker compose exec ... keyorix` lines as it does `docs/UPGRADING.md`. This `README.md` is not a
fragment.
