### Testing

- Fuzz wall-clock hang oracles (`fuzzutil.Guard`, the hostile-server harnesses, the encryption hang guards and several third-party targets) now tell a hung call from a frozen fuzz process before reporting: a deadline miss while the process was frozen gets one more full limit; test-only change.
- `fuzzutil.EffectiveElapsed` (elapsed minus process-frozen time, for `elapsed > ceiling` oracles) and `FUZZ_STALL_LOG` (appends one line per detected freeze, to measure how often the boxes freeze).
