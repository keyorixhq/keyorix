# errtext classification exceptions: one file per function

`TestNoErrorTextClassification` (ERRSTRING-CLASS-1) fails on a function that reads
`err.Error()` text to classify an error, unless the function has a row here, and it fails on a row
whose function no longer reads error text. That two-way check is why this was one file per entry
(GUARD-COLLISION-NOV-1): with one shared TSV, a PR that migrated a handler family deleted rows and a
PR that added a function appended one, and the merge queue tested the two together.

## Adding or removing a row

- One file per function, holding exactly one row: `path:Func<TAB>reason`.
- The file name is the key with `/` and `:` replaced by `__`, plus `.tsv`:
  `server/http/handlers/catalog.go:CreateProject` lives in
  `server__http__handlers__catalog.go__CreateProject.tsv`. The loader rejects any other name, so a
  key cannot sit in two files.
- The reason is one line a reviewer can check. Do not add a row to excuse a NEW storage-error
  classifier: type the refusal instead (`storage.ErrInvalidGroupRequest`,
  `core.ErrPermissionDenied`, see `internal/core/errors_typed.go`).
- Migrating a function off error text deletes its file in the same PR. Never edit another function's file.
- Files that do not end in `.tsv` (this README) are ignored.

## Reason families

- `HTTP`: server/http/handlers, unmigrated (INV-HTTP-classify-errors-by-sentinel-not-text); one
  family per PR (ERRLOSS-SENTINELS-1 task 3). Delete the files with each family's PR.
- `DRIVER`: a database driver's own message (no typed error exists to match).
- `OWNED`: code another running session owns; not edited by ERRSTRING-CLASS-1.
- `GRPC`: gRPC mapper still reading text for refusals core has not typed yet (listed per row).
