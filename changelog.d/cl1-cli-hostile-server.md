### Testing
- **CL1 hostile-server fuzz target against the CLI transport (`cli/cmd.FuzzCLIHostileServer`).**
  Drives the real hardened API client (`apiclient.NewHardenedHTTPClient`: 10 MiB response
  cap, redirect refusal, request timeout) and the `cli/cmd` response-parsing/printing paths
  against a live `httptest` server returning mutated, truncated, oversized, slow,
  redirecting and type-confused replies. Oracles: no panic/hang, air-gap (no non-loopback
  dial — a 3xx `Location` to the cloud-metadata IP must never be dialled), no bearer-token
  forwarding to a redirect target, fail-closed on malformed/oversized/truncated replies, the
  10 MiB size cap, no terminal escape or secret echo in anything the CLI prints, and exit
  codes matching the documented table. Complements `FuzzApiError`, which fuzzes `apiError`
  in isolation and never exercises the transport. The hardening/oracles are red/green-proven
  by `TestCLIHostile_RedGreen_*` (hardened vs. a deliberately un-hardened client). Uses
  `internal/fuzzutil/resguard` (NetMeter air-gap + Probe meters) as a test-only dependency.
