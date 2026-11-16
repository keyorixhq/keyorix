# internal/fuzzutil/boundedwork invariants

Read this before changing anything in `internal/fuzzutil/boundedwork`. It is the
BW1 super-linear-growth fuzz oracle: `Check`/`Analyze` measure a function's time
and allocation across scaled variants of one input (factors 1,2,4,8) and fail
when the cost curve is clearly super-linear (quadratic or worse). The rules below
are the ones that make it fire on a real quadratic (the yaml.v3 duplicate-key
defect, calibrated in `internal/libconformance/yaml_boundedwork_calibration_test.go`)
without false-tripping on a linear parser. Breaking any of them silently turns the
detector into a green check that no longer covers what its name implies.

Format: `INV-BOUNDEDWORK-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-BOUNDEDWORK-<slug>.md`, one per file.
