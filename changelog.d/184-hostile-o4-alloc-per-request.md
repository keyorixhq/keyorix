### Testing

- `hostile` harness: O4 BOUNDED-WORK gains `Config.AllocPerRequest`, a per-request allocation allowance (default 0, unchanged for other targets). `FuzzHealthscanHostileVault` sets it to 3 x `httpsafe.MaxResponseBytes`: a scan reads up to 10 MiB per response over many requests, so the flat 256 MiB limit flagged bounded work (#184).
