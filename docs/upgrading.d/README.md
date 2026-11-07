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

Folding in: releases do not assemble `docs/UPGRADING.md` with a script, and no generator exists for
it. Whoever prepares the release reads this directory when they write the release's
sections: for each fragment, in file-name order, they take the next free section number (`6aa`,
`6ab`, ...), paste the text into `docs/UPGRADING.md` under that numbered heading, fix any
cross-reference, and delete the fragment in the same commit. A fragment that is still here after the
release it names has shipped is a defect.

Reader: `go test -run 'TestUpgradingFragments' ./internal/docsdrift/` fails on a fragment with a name
that is not a lower-case slug, an empty one, or one with a numbered `## 6x` heading.
`TestUpgradingSectionReferencesResolve` already walks every `.md` under `docs/`, so a `§6q`
reference in a fragment must name a heading that exists in `docs/UPGRADING.md`.
`TestDockerDocsAdminCommandsAreRunnable` (`server/admin`) reads the fragments for
`docker compose exec ... keyorix` lines as it does `docs/UPGRADING.md`. This `README.md` is not a
fragment.
