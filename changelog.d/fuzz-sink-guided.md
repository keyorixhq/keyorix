### Testing
- Added `scripts/fuzzing/sinkmap`, an offline deterministic sink-mapper that
  lists dangerous call sites in the root module by kind, resolves each one's
  enclosing function, API/parser reachability and fuzz coverage over a static
  call graph, and emits a ranked machine-readable table to guide where fuzz
  harnesses are pointed next.
- Added three sink-guided fuzz targets chosen by that mapper, one per invariant
  family: `FuzzWebhookSSRFGuard` (notification webhook/chat SSRF guard refuses
  private/link-local destinations), `FuzzSafePathConfinement` (config key-file
  paths cannot traverse outside their base directory), and
  `FuzzPostgresRotateRecordingDriver` (the role-rotation `ALTER ROLE` statement
  keeps attacker-influenced bytes inside their quoted slots, checked by a
  recording driver).
