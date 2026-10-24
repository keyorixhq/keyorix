### Documentation

- ADR-121 (Accepted): how `internal/core` is split — tests move first, the kernel stays, production code leaves only as pure leaves (`docs/adr-121-core-package-split.md`).

### Internal

- Guardrails for the `internal/core` split (INV-CORE-package-boundaries): extracted packages never import core, core's keyorix dependencies are an exact list and any added after the split are registered leaves, test-only packages stay test-only, every core file has one owner cluster (`internal/core/CLUSTERS.d/`), source-scanning guards walk the whole core family (`srcpath.CoreFamilyGoFiles`, registry in `internal/testutil/srcpath/corefamily.d`), and file names named by guards must exist.
- `scripts/refactor/provemove` proves a refactor only moved declarations (test/non-test/ignored file class, GOOS/GOARCH suffix, `//go:` directives, build constraints and const iota positions included; `-alias leaf=core` checks a leaf extraction's aliases; an empty proof fails); `scripts/refactor/coretestclass` and `measure-core.sh` print the black-box test and build-cache numbers extraction PRs paste.
