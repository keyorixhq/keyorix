### Testing
- Added `scripts/fuzzing/sinkmap`, an offline deterministic sink-mapper that
  lists dangerous call sites in the root module by kind, resolves each one's
  enclosing function, API/parser reachability and fuzz coverage over a static
  call graph, and emits a ranked machine-readable table to guide where fuzz
  harnesses are pointed next.
