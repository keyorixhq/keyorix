### Documentation

- ADR-116 (Proposed): how `internal/core` is split — tests move first, the kernel stays, production code leaves only as pure leaves (`docs/adr-116-core-package-split.md`).

### Internal

- Guardrails for the `internal/core` split (INV-CORE-package-boundaries): extracted packages never import core, core's keyorix dependencies are an exact list, test-only packages stay test-only, every core file has one owner cluster (`internal/core/CLUSTERS.d/`), source-scanning guards walk the whole core family (`srcpath.CoreFamilyGoFiles`), and file names named by guards must exist.
- `scripts/refactor/provemove` proves a refactor only moved declarations; `scripts/refactor/coretestclass` and `measure-core.sh` print the black-box test and build-cache numbers extraction PRs paste.
