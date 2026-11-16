### Testing
- **Message-level (structure-aware) hostile-server fuzzing of the PostgreSQL (pgx)
  and MySQL client paths.** Complements the byte-level hostile-server harnesses
  (PR #4136) with generators that emit structurally-valid wire messages carrying
  field-level disagreements: for PostgreSQL, pgproto3-generated
  RowDescription/DataRow/Notice/Error with mutated OIDs, format codes, column
  counts and message order (`fuzz/thirdparty/pgx`, `FuzzPgxMessageLevel`,
  `FuzzPgxResponseMixing`); for MySQL, hand-built text result sets with mutated
  column-count/type/flags and LOCAL INFILE requests (`fuzz/thirdparty/mysql`,
  `FuzzMySQLMessageLevel`, `FuzzMySQLResponseMixing`, `FuzzMySQLLocalInfile`).
  New sound oracles, each with a red proof: TLS never silently downgrades under a
  required mode (pgx `sslmode=require` rejecting a `'N'` negotiation byte; MySQL
  `tls=true` rejecting a server that clears the SSL capability flag), LOCAL INFILE
  canary-file egress refused by default, no credential leak in driver error text,
  server→client decoding parity, and no cross-statement response contamination.
  No production code changed; no real database or network required (loopback
  hostile servers).
