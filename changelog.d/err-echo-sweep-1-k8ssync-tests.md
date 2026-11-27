### Changed
- Added a table-driven test of the Kubernetes sync fetcher's error sites against server-controlled text (secret-state refusal envelope, non-2xx bodies, environment and secret lists, transport). It also pins two open findings, a redirect `Location` and a malformed HTTP response head reaching the returned error, as expected-echo rows until they are fixed.
