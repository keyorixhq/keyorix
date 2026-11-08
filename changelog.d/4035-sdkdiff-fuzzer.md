### Testing
- **Cross-SDK differential fuzzer (`scripts/e2e/sdkdiff`).** Runs one scenario through the Go, Node, Python and Java client SDKs behind a recording proxy and compares the wire requests, results and error classes. Test tooling only: nothing ships in the server or a release. A run that executed nothing fails instead of passing, and the proxy forwards request targets byte for byte.
