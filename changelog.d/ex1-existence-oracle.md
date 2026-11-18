### Added

- Test-only EX1 existence/enumeration oracle with a deterministic COST proxy
  (`server/http/existence_cost_oracle_fuzz_test.go`): for a zero-authority actor it compares an
  existing-but-forbidden id against a same-shape absent id across HTTP status, normalised error
  text, response-body length bucket, information-bearing headers AND the resguard `DBMeter`
  DB-query/rows delta — extending oracle 7 (status-only) into the length/timing dimensions it
  named as uncovered. Includes a census over every single-id GET/DELETE op, an id-encoding fuzz
  target (`FuzzEX1ExistenceCost`), an account-existence login pair, and a per-dimension red/green
  of the detector. New guard `INV-HTTP-denial-cost-existence-independent`.
