- **INV-CONNECT-awssm-2xx-intercept** The AWS Secrets Manager connector's HTTP client
  (`awssm.go`) never lets a 2xx non-200 response body reach the smithy-go SDK's
  `deserializeError` parser. `requireHTTP200` / `status200Client` intercepts every
  response with status ≥ 201 and ≤ 299, closes its body immediately (preventing
  allocation), and returns `unexpectedSuccessStatusError` before the SDK runs.
  For 4xx/5xx responses, `sizeCappedRoundTripper` from `newConnectHardenedTransport`
  caps the body at 1 MiB (`connectMaxResponseBytes`) before the SDK's error parser
  reads it; measured worst-case allocation at the 1 MiB cap is ~5.4 MB (5.1× wire
  bytes), well within the test's bounded-work budget (16 MiB + 2 × wire-bytes).
  This provides equivalent protection to Azure's `errorBodyScrubRoundTripper` for
  the 2xx non-200 case, via a different mechanism suited to the smithy-go SDK path.
  Why: LIBKNOWN3 sibling check after the Azure KV amplification fix
  (`fix(connect): scrub azure 2xx non-200 response bodies before SDK JSON parsing`,
  3ccb06c29); a 20000-level deeply-nested ~40 KB body triggered ~574 MiB on the
  Azure path before that fix; AWS is bounded by construction.
  Guard: `TestAWSSM_NestedErrorBodyDoesNotAmplifyMemory` (bounded-work budget, 13 cases) and
  `TestAWSSM_Non200TwoxxBodyIsNotParsedBySDK` (2xx intercept, 5 status codes) in
  `awssm_errorbody_test.go`. **Not covered**: the success (200) path's allocation
  beyond the 1 MiB cap (covered by `FuzzAWSSMHostileEndpoint` O4 oracle), and
  `FuzzAWSSMConnectorResponse`'s un-capped client (UNGUARDED, #4531).
