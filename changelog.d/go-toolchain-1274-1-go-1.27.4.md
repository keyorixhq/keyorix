### Security
- **Go toolchain bumped from 1.27.3 to 1.27.4 (GO-2026-6859).** The stdlib `net/http` HTTP/1 server race in `MaxBytesReader` (it sets `Connection: close` without synchronization, racing with a handler writing headers; CVE-2026-97054) is reachable from our SAML ACS path (`CompleteSAML` -> `PostFormValue`) and is fixed in go1.27.4. `go.mod`, `operator/go.mod`, the devtools modules, every CI workflow `go-version` and the fuzzing CT script now pin 1.27.4. No `docs/govulncheck-exceptions.d/` row was added: the bump is the fix.

### Internal
- **CI static-analysis unblocked.** `scripts/ci/check-govulncheck.sh` was failing `static-analysis` (and `build-and-test`) for every PR and merge-queue entry on the unfixed stdlib finding.
