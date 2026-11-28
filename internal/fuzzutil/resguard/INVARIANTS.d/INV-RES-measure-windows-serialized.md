- **INV-RES-measure-windows-serialized** Every `Probe.Measure` in a process
  holds one process-wide lock for its whole window, so two measured inputs
  never overlap and the whole-process `ReadMemStats` delta behind
  `alloc_bytes`/`mallocs` (and the GC-baselined `live_heap` delta) contains no
  other MEASURED input's allocations. This holds across Probes (several fuzz
  bodies, `t.Parallel` tests or calibration loops in one binary). The wait is
  bounded and never blocks forever: a target that calls `Measure` INSIDE a
  `fuzzutil.Guard` closure (the three kinopenapi targets) leaves its window held
  when Guard abandons a hung fn, whether the fn took the window before Guard
  gave up on it or after (kinopenapi `schema_boundedwork` parses inside Guard
  before it calls Measure). A waiter therefore gives up AT ONCE while
  `fuzzutil.AbandonedRunning()` (abandoned guarded fns that have not returned
  yet) is above zero, so the next guarded input is not held past its own Guard
  deadline and blamed for the earlier hang, and otherwise after
  `measureLockWait` (2·`GuardTimeout`, for a legitimately long concurrent
  window). An abandoned fn that never returns keeps the gauge above zero for
  the rest of the process, so later CONTENDED windows there are flagged and run
  unserialised at once (an uncontended Measure always gets the lock). It then runs UNSERIALISED and says
  so: `Cost.WindowShared` is set, its
  alloc and live-heap meters are left unmeasured (`AllocSampled`/`Sampled`
  false, so `Budget.Check` skips them under INV-RES-sampled-meters-skip-cheap-inputs
  and never reads a shared delta as this input's), one line goes to stderr per
  stuck episode, later inputs skip the wait while it stays stuck, and
  serialisation resumes once the hung fn returns. The wait polls `TryLock` with
  `time.Sleep`, which allocates nothing, so a waiter does not charge the window
  it waits on. NOT covered: allocations by goroutines outside any `Measure` (the
  fuzz engine, the stall monitor, a goroutine an earlier input leaked, a
  concurrent test body outside its `Measure`) still land in whichever window is
  open, and the seams (`Options.Net/Clock/Log/DB/KDF`) are reset and read per
  window but not per goroutine; on a `WindowShared` input every other
  process-wide meter (goroutines, threads, fds, CPU, write bytes, disk walk,
  seam counts) is still read and judged, and the hung fn may add to it; the only
  signal of an unserialised input is the Cost field and one stderr line per
  episode (no adopter reads the field, which is acceptable because a stuck
  window always follows a Guard failure, so the run is already red); under
  concurrent use with an unrelated abandoned Guard call, a live window can be
  taken for stuck (the waiter is then flagged, not misjudged); a `fn` that
  calls `Measure` itself waits out `measureLockWait` and is then measured
  unserialised. Separate `-parallel`
  fuzz workers are separate processes with their own counters and never needed
  this. Why: RESGUARD-PAR-1 asked for the alloc meter to be immune to concurrent
  measured work. The digitorus false positive it started from turned out to be
  a cold-start cost (INV-FUZZUTIL-first-guard-call-allocates-nothing-extra), but
  overlapping windows are a real second way to charge one input for another's
  allocations: eight 1 MiB inputs measured at once were charged up to 8 MiB
  each. The bounded wait and the abandonment signal come from two Opus reviews:
  with a plain mutex the Guard-around-Measure shape wedged every later `Measure`
  in the process, and with only the time bound the next input's own Guard fired
  first and blamed it (in fuzz minimisation, which accepts any failing candidate,
  that saves a reproducer that does not reproduce). Guard:
  `TestMeasureConcurrentInputsDoNotPolluteEachOther` (red before the lock),
  `TestMeasureConcurrentPlantedBlowUpStillFires` (control: a planted 64 MiB
  blow-up still fires under concurrency while the seven benign inputs pass;
  before the lock they false-fire) and
  `TestMeasureAbandonedWindowDoesNotWedgeLaterInputs` (a held window: later
  inputs return `WindowShared` with unmeasured meters, then serialisation
  resumes) and `TestMeasureInsideAbandonedGuardDoesNotBlameNextInput` (the real
  Guard(Measure) shape: red with only the time bound, the next input reported
  as a 100ms hang it did not cause) and
  `TestMeasureEnteredAfterGuardAbandonDoesNotBlameNextInput` (the fn is
  abandoned first and takes the window afterwards: red with a since-lock
  abandonment count instead of the running gauge) in `internal/fuzzutil/resguard/resguard_concurrency_test.go`.
