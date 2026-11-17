- **INV-BOUNDEDWORK-time-arm-is-load-independent** The time arm measures
  process CPU time (`CLOCK_PROCESS_CPUTIME_ID`), takes the MINIMUM over repeats,
  and measures the sizes round-robin; it falls back to best-of-N wall time for a
  whole curve only when there is no CPU clock or the cheapest point is under
  `cpuClockMinNanos` (50 us), and records the clock in `Verdict.TimeClock`. It
  must never go back to median wall-clock time, and the thresholds (MaxDoubling
  3x, the floors) must not be widened to absorb load. Why: on a loaded runner a
  longer run is preempted more often than a short one, so wall time inflates
  super-linearly with input size and a linear parser reads as quadratic. PR
  #4284's merge-queue round failed this way (3.23x), and 20 parallel `-cpu 1` runs
  under a busy loop read 3.88-7.32x on median wall time (20/20 false positives)
  against 2.18-2.31x on this measure for a linear yaml decode (0/20). Contention
  only adds cost, so best-of-N CPU time removes the noise without blunting the
  arm: a real quadratic is quadratic in its own CPU time. Guard:
  `TestCalib_YAMLSequence_TimeArmQuietGreen` (linear decode, time arm judged, must
  stay quiet) and `TestCalib_PlantedQuadraticTime_FiresRed` (same decode plus a
  planted O(n^2) CPU pass with linear allocation, time arm alone must fire,
  3.72-4.05x under the same load), both in `internal/libconformance`, with
  `TestOracle_RedOnQuadraticTime` (`internal/fuzzutil/boundedwork`).
