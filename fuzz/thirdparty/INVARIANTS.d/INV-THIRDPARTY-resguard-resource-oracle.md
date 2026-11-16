INV-THIRDPARTY-resguard-resource-oracle Every byte-parser hostile target under
`fuzz/thirdparty` that this session ported (yaml, bcrypt, burnttoml, goi18n,
gopsutil, gotpm, spf13pflag, precis, ssh, webauthn, smtp) meters each fuzz
execution through `internal/fuzzutil/resguard` and checks the metered Cost
against a committed, CALIBRATED budget (`<target>/testdata/resguard-<name>.json`)
IN ADDITION to its existing oracle, which is unchanged. The fatal meter for the
in-memory parsers is `alloc_bytes`/`mallocs` (per-byte slope): a decoder that
allocates super-linearly in its input (the RAM-spike defect class — go-yaml #510
is the worked example, reproduced live in `TestResguardYAMLRedGreen` and, through
go-i18n's YAML route, in `TestResguardGoI18nRedGreen`) fails the input. For smtp
the NetMeter air-gap (any non-loopback dial fails) is the added fatal oracle.

Why: PK2 — real third-party defects were RAM/CPU spikes, not panics, and OSS-Fuzz
hunts crashes not behaviour on Keyorix's call paths. The budget is derived from
the benign corpus (`resguard.Calibrate`), never hand-tuned
(`INV-RES-budget-calibrated-not-handtuned`). Regenerate with
`go test -run 'TestResguard.*Calibrate' ./<pkg> -args -rgwrite`.

Deliberately NOT guaranteed: cpu_ns/wall_ns/goroutines are resguard ADVISORY
meters (process-wide, load-noisy) — recorded and reported but never fatal alone,
so a purely-CPU amplifier (e.g. the bcrypt cost-bomb) is NOT caught by this layer;
bcrypt's cost-bomb stays guarded by the harness's existing cost-skip. Where a
library had no natural super-linear amplifier (burnttoml, precis, gopsutil,
spf13pflag, gotpm, webauthn, ssh — all found robustly linear/bounded on probing),
the red/green is a budget self-test (a 10×-ceiling alloc must trip the calibrated
budget), making the oracle a watched regression tripwire, not a live-defect catch.

Guard: `TestResguardYAMLRedGreen`, `TestResguardGoI18nRedGreen` (real amplifier,
alloc) and the sibling `TestResguard<Name>RedGreen` / `TestResguard<Name>Calibrate`
in each package | the completeness of the target LIST above is UNGUARDED (no test
asserts every byte-parser target carries a resguard budget).
