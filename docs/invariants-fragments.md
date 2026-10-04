# Invariant fragments: `<pkg>/INVARIANTS.d/<ID>.md`

Every core package documents its invariants in `<pkg>/INVARIANTS.md` (index:
[`docs/INVARIANTS.md`](INVARIANTS.md)). This page defines a second, additive layout for the
same entries: **one invariant per file**, in `<pkg>/INVARIANTS.d/<ID>.md`. Both layouts are
read together by the doc guard,
`internal/statemap/invariants_fragments_guard_test.go`, and share one ID namespace.

## Why

A single shared `INVARIANTS.md` per package is a merge-conflict magnet, and its sequential
IDs collide silently:

- **Conflicts.** At the time of writing (2026-10-04), 15 open PRs touched
  `internal/core/INVARIANTS.md`, 9 touched `internal/storage/store/INVARIANTS.md`, 4
  `internal/storage/INVARIANTS.md`. Every one of them appends to the end of the same section,
  so every merge conflicts with every other.
- **ID collisions.** Each PR appends "the next number". Two PRs written against the same base
  pick the same number, git merges both bullets cleanly (they're in different places, or the
  conflict is resolved by keeping both), and the file ends up with two different rules under
  one ID. This has already happened: `main` defines **`INV-CORE-41` twice** in
  `internal/core/INVARIANTS.md` (the GUARD-2 exempt-TSV rule and the cross-replica
  `WithNamedLock` serialization rule). In the open queue at the same time, #2612 and #2632
  each add yet another `INV-CORE-41`, #2626 and #2632 another `INV-CORE-42`, and eight PRs
  (#2632, #2664, #2665, #2671–#2675) each add an `INV-STORE-21` — four different rules
  between them.
- **Nothing checked it.** Before the doc guard, no test or script read any `INVARIANTS.md`.

A fragment is a new file, so two PRs adding two fragments never conflict. A slug ID is
derived from what the invariant protects, not from a counter, so two PRs written against the
same base do not pick the same ID by accident — and if they do (same slug for the same
file name), git reports an add/add conflict instead of silently keeping both.

## The convention

- **Location:** `<pkg>/INVARIANTS.d/<ID>.md`, next to `<pkg>/INVARIANTS.md`. The directory
  needs a sibling `INVARIANTS.md` (it declares the prefix and holds the prose and section
  headings); an orphan `INVARIANTS.d/` fails the guard.
- **ID:** `INV-<PKG>-<kebab-slug>`, e.g. `INV-CORE-mfa-purpose-binding`. `<PKG>` is the prefix
  declared on the package file's own `Format:` line (`INV-CORE`, `INV-STORAGE`, `INV-STORE`,
  `INV-ENCRYPTION`, `INV-AUDITVERIFY`, `INV-MW`, `INV-HTTP`, `INV-GRPC`, `INV-GRPCSVC`,
  `INV-CLI`, `INV-WEB`). The slug is lowercase letters/digits separated by `-`, starting with a
  letter. Name it for what is protected, not for the PR or the date. Legacy numeric IDs
  (`INV-CORE-07`) remain valid — in `INVARIANTS.md`, and in fragments produced by migrating
  them — but **new** invariants should use a slug.
- **File name = ID:** `INVARIANTS.d/INV-CORE-mfa-purpose-binding.md` defines exactly
  `INV-CORE-mfa-purpose-binding`.
- **Content:** exactly one bold ID, as the first line, in the same bullet shape as the package
  file, then optionally a section marker:

  ```markdown
  - **INV-CORE-mfa-purpose-binding** Every MFA step-up consume pins a hardcoded purpose
    constant. Why: confused-deputy step-up bypass. Guard:
    `mfa_stepup_purpose_guard_test.go:TestMFAStepUpConsumersUseExpectedPurpose`.
  <!-- section: Authorization ceiling -->
  ```

  Refer to other invariants in plain text (`INV-CORE-17`), never in bold — a second bold ID
  makes the fragment fail "exactly one definition".
- **`Guard:` or `UNGUARDED (#issue)`** is required in every slug-ID fragment.
- **Section marker** (optional): `<!-- section: <heading> -->` names a `## <heading>` in the
  sibling `INVARIANTS.md`; the guard fails if no such heading exists. It is an HTML comment so
  it renders invisibly.

## What the doc guard enforces

`internal/statemap/invariants_fragments_guard_test.go` (runs in CI's root catch-all leg with
the rest of `internal/statemap`), over every `INVARIANTS.md` except the `docs/INVARIANTS.md`
index, plus every `INVARIANTS.d/`:

| Rule | Applies to |
|---|---|
| No ID defined twice (within the file, within `INVARIANTS.d/`, or across them) | all |
| Every ID carries the prefix from the package's `Format:` line | all |
| Legacy `INVARIANTS.md` bullets use numeric IDs (slugs belong in fragments) | legacy |
| Exactly one bold `**INV-...**`, as a first-line `- **ID**` bullet | fragments |
| File name minus `.md` equals the ID; suffix is numeric or a kebab slug | fragments |
| `INVARIANTS.d/` has a sibling `INVARIANTS.md` and holds only `*.md` files | fragments |
| States `Guard:` or `UNGUARDED` | slug-ID fragments only |
| `<!-- section: X -->` names an existing `## X` heading | fragments |
| The index defines no invariants and has no `INVARIANTS.d/` | `docs/INVARIANTS.md` |

Every rejection path has a fixture case in `TestInvariantDocs_Fixtures` (an `fstest.MapFS`),
and `TestInvariantDocs_RealRepo` runs the same checker over the real tree.

**Why `Guard:`/`UNGUARDED` is not enforced on legacy bullets:** it does not hold on `main`.
Six legacy bullets state neither — `INV-CLI-02`, `INV-CLI-12`, the second `INV-CORE-41` (it
says "Guard (regression, …)"), `INV-ENCRYPTION-26`, `INV-STORAGE-33`, `INV-GRPC-06` — mostly
"not a gap, by design" entries. Enforcing it repo-wide needs those reworded first, in files
that many open PRs touch. Migrated numeric fragments inherit the same exemption.

**Known duplicates:** `knownDuplicateInvariantIDs` in the guard grandfathers `INV-CORE-41`
only. The guard also fails if a grandfathered ID is no longer duplicated, so the list can
only shrink: renumbering one of the two `INV-CORE-41`s makes the test red until the entry is
deleted. No other duplicate exists on `main` (the real-tree run is green with that one entry).

What the guard does **not** check: that a named guard test exists or passes (that is
`scripts/check-closures.sh`'s / `check-adr-conformance.sh`'s job for ledgered claims), that an
issue number is real or open, or the hand-maintained count table in `docs/INVARIANTS.md`.

## Adding an invariant

Create `<pkg>/INVARIANTS.d/INV-<PKG>-<slug>.md` as above. Do not append a bullet to
`INVARIANTS.md` and do not take "the next number". Run
`go test ./internal/statemap/ -run InvariantDocs`.

## Migrating a package (coordinator, in a quiet window)

`scripts/ledgers/migrate-invariants-to-fragments.sh` moves every column-0
`- **INV-…**` bullet (with its indented continuation lines, verbatim) from `INVARIANTS.md`
into `INVARIANTS.d/<ID>.md`, appending a `<!-- section: … -->` line for the `## ` heading it
sat under. Prose, headings and non-invariant bullets stay in `INVARIANTS.md`, which gains a
one-paragraph pointer under its `Format:` line. It is deterministic and idempotent (a second
run is a no-op), validates every target package before writing anything, and refuses with no
changes — printing what to renumber — if any target has a duplicate ID.

```sh
# every package except internal/core (blocked by the duplicate INV-CORE-41 until renumbered):
scripts/ledgers/migrate-invariants-to-fragments.sh \
  internal/storage internal/storage/store internal/encryption internal/auditverify \
  server/middleware server/http server/grpc server/grpc/services cli web/src
go test ./internal/statemap/ -run InvariantDocs -count=1

# after INV-CORE-41 is renumbered and its knownDuplicateInvariantIDs entry deleted:
scripts/ledgers/migrate-invariants-to-fragments.sh --all
```

`--dry-run` lists what would move. Run it only when no open PR edits the package's
`INVARIANTS.md`: a migration rewrites the whole file, so every open PR touching it would have
to be rebased onto fragments.

Migration is opt-in per package, not automatic, for that reason. Until a package is migrated,
both layouts coexist: legacy numbered bullets stay where they are and new invariants go in as
fragments, and the guard treats both as one namespace.

After migrating, `docs/INVARIANTS.md`'s counts are re-derived from fragments
(`ls <pkg>/INVARIANTS.d | wc -l`; per fragment, whether it contains `UNGUARDED`) instead of
by counting bullets.
