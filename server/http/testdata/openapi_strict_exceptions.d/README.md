# openapi_strict_exceptions.d

The SHRINK-ONLY exceptions list for the STRICT FuzzOpenAPIStateful gate (oracle 1:
no undeclared 5xx). One file per (operation, status) that strict mode would
otherwise fail on, each a REAL still-unfixed undeclared-5xx defect held so the
nightly strict gate stays green while the fix is pending. One file per row, so two
PRs that triage different operations never edit the same file.

File name: `<operation>.tsv`, a single tab-separated row (the loader rejects a file
whose name does not match its operation column):

    operation  status  verdict  issue  owner  reason

- `verdict` is one of `mapped-wrongly`, `missing-sentinel`, `genuinely-internal`.
- `issue` is `#NNNN` if repo docs/code name one, else `NEEDS ISSUE`.

Enforced by `TestOpenAPIStrictExceptions` (`server/http/openapi_strict_exceptions_test.go`):

- CAN ONLY SHRINK: every row's deterministic reproducer must still return the listed
  undeclared 5xx against the real router. A row whose defect was fixed (no longer
  5xx) FAILS the test, forcing its removal (delete the file).
- CANNOT GROW SILENTLY: the (operation, status) set here must EXACTLY equal the
  waiver set the fuzzer consults (`osKnownUndeclared5xx`). A new undeclared 5xx
  cannot be waived in the fuzzer without a file here (with issue + owner), and no
  file can exist without a matching fuzzer waiver.
