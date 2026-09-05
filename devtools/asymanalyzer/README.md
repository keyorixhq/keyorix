# asymanalyzer

Finds every repo-defined Go interface with 2+ concrete implementers, via
`golang.org/x/tools/go/packages` + `go/types.Implements` — not grep. Backs the
`family-membership-check` CI job (`.github/workflows/family-check.yml`) and the
implementation-asymmetry scan method (see
`keyorix-private/adversarial-review/IMPLEMENTATION-ASYMMETRY-SCAN-2026-09-05.md`
for the finding history that motivated this becoming a CI check rather than a
one-off report).

A standalone Go module (like `operator/`) so `golang.org/x/tools` never becomes
a dependency of the shipped `keyorix` binary — build/run with `GOWORK=off`.

## Usage

```
GOWORK=off go build -o asymanalyzer .
GOWORK=off ./asymanalyzer [-json] [-root <repo-root>] <dir> [<dir> ...]
```

`-root` makes reported file paths relative to a common base (default: the
first `<dir>`), so paths from a separately-scanned module like `operator/`
still read as `operator/internal/foo/bar.go` — matching `git diff --name-only`
output from the outer checkout, which is what the CI job diffs against.

Only finds interface-unified families — it cannot find sibling packages doing
the same job without a shared interface (the SIEM-forwarder case from the
2026-09-05 report) or parallel function-naming families
(`rotateAWS`/`rotateAzure`/...). Those need a human/agent pass, not this tool;
`family-check.yml`'s scope list (`.github/family-check-scope.json`) is where
those non-interface families get added by hand when found.
