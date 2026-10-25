- **INV-ENCRYPTION-redo-marker-kept-for-the-pending-keydir** On PostgreSQL, where several key
  directories can serve one database (`key_dir_lock: database`, the Helm chart's Secret mode, a key
  copy per host), the DEK-rotation redo marker is cleared only by the key directory that holds
  `dek.key.pending` (it promotes it), or once the database's DEK epoch proves the clearing
  directory already holds the new DEK (`clearCompletedRotationMarker`: the epoch comparison is
  part of the DELETE; run after the epoch guard verifies at start-up, and before a rotation stages
  its own pending DEK). `RecoverInterruptedRotation` in a directory without the pending file
  leaves the marker. Before HA-SECRET-KEYS-1 it cleared it, so a replica booting with another key
  directory between a rotation's sweep commit and its rename made the rotating directory's next
  recovery discard the only copy of the new DEK (every row lost). SQLite (one key directory) is
  unchanged. Guard:
  `rotation_marker_other_keydir_postgres_test.go:TestDEKRotation_Postgres_RecoveryInAnotherKeyDirKeepsTheRedoMarker`,
  `:TestDEKRotation_Postgres_RotateFromStaleKeyDirKeepsTheRedoMarker`,
  `:TestDEKRotation_Postgres_CompletedRotationMarkerClearedOnceEpochMatches`,
  `:TestDEKRotation_Postgres_RotationClearsALeftoverMarkerBeforeStaging` (pg-gated).
  **Not covered**: a database without a DEK epoch row on PostgreSQL (every server since #3344
  seeds it at start-up); a leftover marker in a key directory whose server never starts again
  stays until the next rotation there.
