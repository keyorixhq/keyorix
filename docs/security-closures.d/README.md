# docs/security-closures.d/ — one security closure per file

Each file is named `<claim_id>.tsv` and contains exactly one tab-separated row:
`claim_id  package  proving_test  verification  landed_commit  issue  note` —
the same row shape `docs/security-closures.tsv` has always used. See
`docs/security-closures.tsv`'s own generated header (`HEADER.txt` here) for
what each column means and what `verification` values are valid.

## Adding a closure

Add a new `<claim_id>.tsv` file here, then run:

```
scripts/gen-security-closures-tsv.sh
```

to regenerate `docs/security-closures.tsv`, and commit both.
`scripts/check-closures.sh` (and `scripts/check-adr-conformance.sh`, which
reuses it) keep reading the generated flat file unchanged — nothing about
verification behavior changes, only how the ledger is authored.

**This is the whole point of the split**: a new closure is a new file, so two
PRs closing two different findings never touch the same line and never
conflict. Before this, every closure PR appended a line to one shared
`docs/security-closures.tsv`, and any two such PRs open at once were a
guaranteed merge conflict (`COMMON-RULES.md`'s "Shared-file rule") — this
directory replaces that with one-file-per-claim, mirroring
`scripts/fuzzing/targets.d/`'s fix for the identical problem with fuzz
targets.

`EXCLUDED.md` in this directory lists claims deliberately NOT represented as a
file here (a documented exception whose test doesn't yet exist) — the
generator does not read it; it is a human note only.
