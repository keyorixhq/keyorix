- **INV-ADMIN-keylifecycle-interrupted-rotation-auto-recovers** A DEK rotation whose
  process is SIGKILLed at any point needs no manual hand-repair: the documented recovery
  command (`encryption upgrade-aad` / `UpgradeAADWithConfig`, or any key-writing command /
  server boot) runs `RecoverInterruptedRotation` first, which promotes `dek.key.pending`
  when the DB redo marker (`dek_rotation.promote_pending`) shows the sweep committed and
  discards it otherwise — leaving exactly one of the old/new DEK consistently active and
  every acknowledged secret decryptable, and the store fully usable. Why: #4105 (a crashed
  rotation must not leave a state an operator has to hand-repair); permanent data loss is
  least visible at the process boundary. Guard: `server/admin/keylifecycle_process_fuzz_test.go`
  `TestKLRedProof_OracleD_Recovery` (a real rotation child SIGKILLed after its sweep
  COMMIT, before the promote; red: the store opened without recovery cannot decrypt the
  acknowledged write; green: after the recovery command the new DEK is promoted and it
  decrypts), `TestKeyLifecycleProcessReplay` (`create_kill_rotate_*`: one case per kill
  phase, each asserting where its kill landed) and `FuzzKeyLifecycleProcess` op 7
  (`klStepKillRotate`: after recovery no pending file, dek.key is the new DEK exactly when
  the sweep had committed, every acknowledged write decrypts). The in-process
  numbered-checkpoint red/green of the same window is owned by `internal/encryption`
  (`TestRotateDEKWithSweep_KillAfterSweepCommitBeforePromote_RecoversCleanly`,
  `FuzzDEKSweepCrashConsistency`).
