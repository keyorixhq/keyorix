### Testing

- Fuzz wall-clock hang oracles (`fuzzutil.Guard`, the hostile-server harnesses, the encryption hang guards and several third-party targets) now tell a hung call from a frozen fuzz process before reporting: a deadline miss while the process was frozen gets one more full limit; test-only change.
- The grace is refused when the input caused the freeze itself (heap allocation or GC CPU growth in the window, read from `runtime/metrics`), and it forgives only the frozen time: a call that ran longer than its limit while the process was running still fails. Every excused miss is logged to stderr and `FUZZ_STALL_LOG`.
- `fuzzutil.OverDeadline` (bounded-work oracle for timed synchronous calls: fails above 2x the deadline of wall time, when running time exceeds the deadline, or when the freeze was self-inflicted) and `FUZZ_STALL_LOG` (appends one line per detected freeze and per excused miss, to measure how often the boxes freeze).
