- **INV-AUDITVERIFY-witness-file-torn-never-valid** A post-crash or tampered audit high-water
  witness file is never accepted as a valid mark: an EXISTING but unparseable witness is
  surfaced as an error by `ReadWitness` (never `found=false,nil` "no witness" — that would be a
  rollback-protection bypass), and a witness whose bytes were not produced by signing a
  checkpoint under the real key fails `HighWaterSigMatches` (the HMAC is the witness's integrity
  guard). A legitimate higher advance over a replayed state never yields a readable mark lower
  than an already-acknowledged one, and advancing over an unparseable witness surfaces the error
  rather than silently clobbering it. Why: witness.go `ReadWitness`/`WriteWitnessIfHigher` doc
  comments; `docs/design-b3-backup-v2.md` §6.3. Complements INV-AUDITVERIFY-10 (a single
  monotonicity unit case) and INV-AUDITVERIFY-15 (row decode, not the witness file) with a
  corpus-driven crash-replay target that manufactures torn/forged/truncated/rewound on-disk
  witness states and drives the real reader/writer. Guard:
  `FuzzWitnessCrashReplay` (witness_crash_replay_fuzz_test.go).
