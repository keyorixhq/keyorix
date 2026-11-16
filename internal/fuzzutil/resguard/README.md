# resguard — shared fuzz resource-measurement layer

`resguard` measures what a single fuzz input costs across every resource real
Keyorix defects have blown: RAM/CPU spikes (pkcs7 130 B→1.8 GB, the connector
gzip bomb, Azure RetryDelay -1, the bcrypt hang) and the dimensions nothing
previously metered — disk, inodes, fds, goroutines, threads, network dials,
virtual-time sleeps, log volume and DB query cost.

It is **test-only** (nothing outside `*_test.go` imports it;
`TestResguardImportedOnlyFromTests` enforces that) and it **composes**
`internal/fuzzutil/complexity` rather than duplicating its allocation meter.

## Why a separate package (not an extension of `complexity`)

`complexity` is a pure leaf — it imports only `runtime` and `time` so it adds
nothing to a fuzz binary's coverage map beyond the standard library, and answers
one question: did allocation per input byte stay bounded. `resguard` needs
`testing`, syscalls, `/proc`, `http.RoundTripper` and gorm seams. Folding that
into `complexity` would bloat the leaf every alloc fuzzer links. So `resguard`
calls `complexity.Measure` for the alloc delta (no second copy of the
`ReadMemStats` logic) and adds the environment meters around it.

## Parts

| File | What |
|------|------|
| `resguard.go` | `Cost` vector, `Probe`, cheap vs sampled measurement |
| `platform_linux.go` | getrusage CPU, `/proc` threads/fds/io (Linux) |
| `disk.go` | TempDir walk diff (files, dirs, symlinks, bytes, sparse blocks) |
| `net.go` | counting dialer/transport + **air-gap oracle** (non-loopback dial fails) |
| `clock.go` | virtual-sleep seam (Azure RetryDelay -1 shape) |
| `logmeter.go` | log-byte seam |
| `gormcost.go` | DB query/row seam (gorm callbacks) |
| `budget.go` | `Calibrate` (seed p99 × factor) → `testdata/resguard.json`, `Budget.Check` |
| `buckets.go` | cost-guided coverage buckets (PerfFuzz on `go test -fuzz`) |
| `drift.go` | cross-input leak watcher (live heap / goroutines / fds) |
| `sentinel.go` | secret-leak oracle, **unified with `taint`** |

## Minimal target shape

```go
func FuzzThing(f *testing.F) {
    net := resguard.NewNetMeter()
    p := resguard.New(f, resguard.Options{TempDir: f.TempDir(), Net: net})
    bgt, _ := resguard.LoadBudget("testdata/resguard.json")
    f.Fuzz(func(t *testing.T, data []byte) {
        c := p.Measure(len(data), func() { parse(data) })
        bgt.Check(t.Fatalf, c)
        resguard.FeedCoverage(c)        // keep cost-raising inputs
        if r := p.CheckDrift(c); r != "" { t.Fatal(r) }
    })
}
```

Each oracle's limits are documented in its doc comment: what it measures, and
what it does NOT.
