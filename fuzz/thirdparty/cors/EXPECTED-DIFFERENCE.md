# go-chi/cors — expected, non-defect behaviours

These are documented behaviours of `github.com/go-chi/cors` v1.2.2 that the oracles
treat as EXPECTED, not findings. They matter when reading an O-CORS-3 verdict.

- **Case-insensitive origin matching.** cors lower-cases both the configured origins
  (at `New`) and the request `Origin` before comparing (`isOriginAllowed`), and its own
  doc notes this deviates from the spec's case-sensitive rule on purpose ("as it may be
  error prone, we chose to ignore the spec here"). So `Origin: HTTP://LOCALHOST:3000`
  matches a configured `http://localhost:3000`. The reflected `Access-Control-Allow-Origin`
  is the ORIGINAL-case request value, which still equals the request Origin — O-CORS-1b
  holds. Only matters if the attacker's page already runs at that origin.

- **Wildcard matching is pure prefix/suffix string compare, not URL parsing.** A
  configured `https://*.keyorix.example` becomes prefix `https://`, suffix
  `.keyorix.example`, and `wildcard.match` accepts any string that has both — it never
  parses the origin as a URL. This is by design and only reachable if an operator puts a
  wildcard in `server.http.allowed_origins`; O-CORS-3 pins go-chi's verdict to a
  line-for-line reference port of this exact algorithm, so the two always agree. A
  config author who writes `*keyorix.example` (no dot) would match `evilkeyorix.example`
  — that is an operator footgun, not a go-chi defect, and is out of the exact-config
  reachable set O-CORS-1 guards.

- **Preflight stops the chain with 200.** For `OPTIONS` + `Access-Control-Request-Method`
  + `Origin`, cors handles the preflight and (without `OptionsPassthrough`) writes 200
  without calling the next handler. The sentinel-body check accounts for this.

- **No CORS headers for a disallowed or absent origin.** cors adds only `Vary` and
  returns; the absence of `Access-Control-Allow-Origin` IS the rejection. O-CORS-1/2
  therefore only assert about a PRESENT reflected origin.
