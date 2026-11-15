# Third-party client-library hostile-server fuzzers (h3)

These harnesses attack **third-party cloud-SDK client libraries directly**, through
their public APIs only, with **no Keyorix wrapper in the loop**. A fuzzer-controlled
loopback server (`net.Listen 127.0.0.1:0`, TLS for Azure) feeds the real client
arbitrary HTTP status lines, headers, bodies and wire framing. Any finding therefore
localises to the library (or the stdlib `net/http` response reader under it) and is
upstream-reportable, independent of Keyorix's own response handling.

## Packages

- `aws/` — AWS SDK for Go v2: `secretsmanager.GetSecretValue` (AWS JSON 1.1),
  `sts.AssumeRole` (AWS Query/XML), `kms.Decrypt` (AWS JSON 1.1 blob I/O).
  Targets: `FuzzSecretsManager`, `FuzzSTS`, `FuzzKMS`.
- `azure/` — Azure `azsecrets` Key Vault client over azcore's pipeline (retry +
  bearer-token challenge-authentication). Target: `FuzzAzureGetSecret`. Serves TLS
  because azcore refuses to attach a bearer token over plaintext http.

## Oracles (identical four classes in both packages)

- **(a) no-panic / no-hang / bounded alloc** — op under a client timeout + 20s
  watchdog; a panic in the SDK fails the test. Attacker bytes capped at 64KB/response,
  so unbounded-allocation-from-length-field is probed via lying-Content-Length /
  truncated-chunk (client must error), not by measuring RSS.
- **(b) canary leak** — client built with high-entropy secret canaries (AWS secret
  key + session token; Azure bearer token); asserts they never appear in a returned
  error string or `fmt %+v` of the output. Does not inspect the on-wire request
  (signing/bearer legitimately use the secret).
- **(c) echo class** — server body text copied into an error is EXPECTED, logged
  under `echo:`, never a finding.
- **(d) ignored-read-error** — when the final response the client received declared
  more body than it delivered, the client must error, not return truncated success.
  Keyed on the server's record of the last response actually served
  (`fakeServer.lastResponseTruncated`), mirroring `writeResponse` including net/http's
  no-body-status rule (1xx/204/304).

Each fatal oracle is validated red/green in `*_oracle_validation_test.go`, and the
truncation predicate is pinned to `writeResponse`'s wire behaviour in
`TestSpecTruncates_MirrorsWriteResponse`.

## Running

```
env GOCACHE=... GOMODCACHE=... GOFLAGS= GOMAXPROCS=2 \
  go test ./fuzz/thirdparty/aws/   -run '^$' -fuzz '^FuzzSecretsManager$' -fuzztime 600s -parallel 2
```

Seed corpora (valid exchanges + known-bad shapes) are added via `f.Add` in
`seed_test.go`; discovered crashers live under `<pkg>/testdata/fuzz/<Target>/`.

## Findings

See `/mnt/data/wave4/out/h3-REPORT.md`. Summary: **AZURE-1** — a library panic
(index-out-of-range in `keyvault/internal` `challenge_policy.go` `parseTenant`) is
reachable through `azsecrets.GetSecret` from a malformed server `WWW-Authenticate`
header; minimal reproducer in `azure/repro_panic_test.go`. The AWS targets found no
library defects over the runs recorded in the report.
