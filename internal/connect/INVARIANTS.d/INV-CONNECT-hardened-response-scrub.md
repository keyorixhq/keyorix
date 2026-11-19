- **INV-CONNECT-hardened-response-scrub** The hardened HTTP client's response layer
  (`hardened_client.go`) never leaks a hostile cloud response into an accepted value or an
  unbounded allocation. Specifically, for any response bytes from a compromised/MITM'd
  endpoint: (a) `scrubbedErrorBody` emits only valid JSON of the exact
  `{"error":{"code,message}}` shape whose `code` matches `^[A-Za-z0-9_.-]{1,64}$` and is
  either a charset-clean code that genuinely appeared as the top-level `error.code` or the
  fixed `UpstreamError` sentinel — no attacker byte (quote/backslash/control/newline) and no
  invented or partial code escapes into the body the SDK then parses; (b) `validErrorCode`
  accepts a string iff it matches that same regexp; (c) `cappedBodyReader` delivers exactly
  `body[:min(len,cap)]`, returns `errResponseTooLarge` iff `len > cap`, never exceeds the
  cap, and holds a sticky terminal error — so a size cap bounds work post-decompression;
  (d) `errorBodyScrubRoundTripper` passes a `200 OK` response through unchanged but, for
  any other status (whether `>=300` error status or `2xx` non-200 unexpected-success that
  azcore treats as an error), replaces the body with a scrubbed one, forces
  `Content-Type: application/json`, sets `Content-Length` to the new body length, clears
  `TransferEncoding` / sets `Uncompressed`, deletes `Content-Encoding`/`Content-Range`/
  `Content-Md5`, and preserves the status code and retry/auth headers. The 2xx non-200
  case matters because `azsecrets.GetSecret` only expects 200; azcore parses any other
  response body through `NewResponseError` → `extractErrorCodeJSON` → `encoding/json.Unmarshal`,
  and a hostile server can amplify a ~40 KB deeply-nested body to hundreds of MB via
  recursive JSON processing (confirmed with the saved corpus file, 20000-level nesting). Why: GP1 cloud-identity
  hostile-response campaign (report `/mnt/data/wave4/out/gp1-REPORT.md`); this is the "HTTP
  client layer that parses redirects, content-length and content-type" shared by the Azure
  Key Vault (Azure-identity-authenticated) and Vault/AWS Secrets Manager connectors, and
  underpins `docs/findings/2026-09-19-FINDING-connect-response-trust-gaps.md`. Guard:
  `internal/connect` `FuzzScrubbedErrorBody` (O-SCRUB), `FuzzValidErrorCode` (O-CODE),
  `FuzzCappedBodyReader` (O-CAP) and `FuzzErrorBodyScrubRoundTrip` (O-RT), each red/green
  proven against a planted defect (see the report's RED-PROOF section). **Not covered**: the
  underlying transport's dial/redirect/TLS/HTTP-2 behaviour (those have their own guards and
  the server-driven `FuzzAzureKVHostileEndpoint`/`FuzzAWSSMHostileEndpoint` targets), the
  cloud SDKs' own decode of the scrubbed body, and GCP Secret Manager's gRPC path (not HTTP).
