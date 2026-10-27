- **INV-ENCRYPTION-rotation-protocol-never-older** `RotateDEKWithSweep` refuses, before it
  writes a key file or a row, when the database records a DEK rotation protocol
  (`system_metadata["dek.rotation_protocol"]`) newer than its own `dekRotationProtocol`, or one
  that does not parse. The record is only ever raised: by every server start on PostgreSQL
  (`StartDEKEpochGuard`) and inside every rotation's sweep transaction. So once a database has
  been served by a binary with protocol N, an admin image with protocol < N that reads the
  marker cannot rotate it. Why: an N-1 admin image without the DEK epoch rotated and left
  `dek.epoch` naming the old DEK (DEK-ROTATE-SAFETY-1 item 3, DEK-EPOCH-N1-ROTATION). Guard:
  `rotation_protocol_test.go:TestRotateDEKWithSweep_RefusesNewerRecordedRotationProtocol`,
  `rotation_protocol_unit_test.go`, `sweep_verify_postgres_test.go:TestDEKEpoch_Postgres_StartRecordsRotationProtocol`
  (pg-gated). **Not covered**: binaries that predate the marker (v0.96.x, protocol 1) never read
  it; for them the runbook rule "never rotate with an admin binary older than the servers"
  (docs/operator/key-rotation-runbook.md) is the only protection. Bump `dekRotationProtocol`
  with any rotation change an older binary would get wrong.
<!-- section: First-boot / cross-process coordination -->
