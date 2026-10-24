# srcpath core family registry (ADR-116)

One file per directory of the core family, one row per file:

```
<kind>	<dir>	<reason>
```

Tab-separated; `#` starts a comment line. `dir` is repository-relative, slash-separated and clean.

| kind | meaning | rows |
|---|---|---|
| `core` | the package being split | exactly one (`core.tsv`) |
| `testonly` | a package created for tests only (ADR-116 decision 2): R2 and R3 | one per package |
| `extracted` | a package extracted from internal/core: R1, and every core-family guard (R5) scans it | one per extraction |

An extraction PR adds one file, `<leaf>.tsv`, with `extracted`, the package dir and the PR or brief
that extracted it. Never edit another row to add one (CLAUDE.md, "Test registry tables").
`srcpath` embeds `*.tsv` here and panics at package init on a malformed file, a duplicate dir
or anything other than one `core` row.

Why data and not Go literals: `scripts/ci/select-affected.py` (rule 3) treats a Go string
literal that names a path as a reader of that path. A literal naming internal/core in srcpath's
non-test code made srcpath a CODE seed for every internal/core change, so every package whose
tests import srcpath was re-tested (PR #3695 review, F5). The rows here are not Go literals, so a
core change no longer selects srcpath's importers; a change to this directory still does (an
embedded file is compiled code, and internal/testutil changes run the full suite anyway).
