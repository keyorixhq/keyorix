### Fixed

- `devtools/familycheck`: the PR-body marker (`family-check: intentional` / `new-member-verified`) is now located on the original text. Previously the offset came from a lowercased copy, so a character whose lowercase has a different byte length (for example `İ`) before the marker shifted the slice and the wrong line was checked for the family name.
- `docs/UPGRADING.md` 6j: the recover-admin alerting first pass is described correctly. An install with no stored `recover_admin_alert_last_notified_id` mark scans the audit table from the first row once; an install with a stored mark resumes from it.

### Testing

- `server/grpc/proto_reserved_fields_test.go`: the `.proto` source parser behind the reserved-fields guard (INV-GRPC-05) now has a red/green calibration (a removed field number without a `reserved` entry fails, with it passes) and cases for its blind spots. It now ignores block comments and commented-out message headers, understands `reserved N to max;` and field options, errors on an unparseable reserved item, and lists in its doc comment the forms it does not recognise.
