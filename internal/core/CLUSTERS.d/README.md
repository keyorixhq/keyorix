# internal/core clusters (ADR-121, R4)

Every non-test `.go` file directly in `internal/core` belongs to exactly one cluster.
Each `<cluster>.txt` here lists the files of one cluster: one pattern per line, matched
with `filepath.Match` against the file name; `#` starts a comment line.

- `kernel.txt` lists exact names only: the kernel is not split (ADR-121 decision 1), and a
  new kernel file is a reviewed one-line addition.
- The other clusters use globs where a prefix names the feature (`secret_access_*.go`), so
  most new files already match and most PRs never touch this directory.

`TestEveryCoreFileHasOneCluster` (`internal/core/guards/core_clusters_guard_test.go`) fails
when a file matches no cluster or two clusters, and when a pattern matches no file (stale).
Its message names the nearest cluster by file-name prefix.

The clusters are the candidates of the CORE-SPLIT-DESIGN-1 analysis (section 3.6 of
`reports/SESSION-CORE-SPLIT-DESIGN-1.md`). Being in a cluster does not mean a file may move:
only pure leaves move, one extraction per PR (ADR-121).
