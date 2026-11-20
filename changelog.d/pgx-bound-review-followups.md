### Security

- The pgx claimed-length bound is now pinned end to end: the behavioural test asserts the
  effective `MaxExpectedBodyLen`, the committed pgx and MySQL fuzz budgets are checked against
  the product bound they were calibrated with, and the connect-site guard in `internal/dynamic`
  also flags non-call references to `sql.Open`, `sql.OpenDB` in files that import pgx, methods named
  `connectPostgres` and a mere mention of `pgxlimits.Apply`.
