- **INV-FUZZJWT-kid-only-key-selection** Key selection is driven by issuer+`kid` ONLY; the
  attacker-controllable `jku`, `x5u` and embedded `jwk` headers never cause a key to be
  fetched, dereferenced, or trusted. An RS256 token (an allowed alg) signed by an attacker key,
  carrying hostile `jku`/`x5u`/`jwk` (the `jwk` holds the attacker's real public key) and an
  unknown `kid`, is rejected by the real `oidcverify.OIDCVerifier`, and the JWKS resolver is
  asked exactly once, for `(issuer, "attacker-kid")`. Why: the production keyfunc
  (`OIDCVerifier.VerifyWithExpiry`) reads only the issuer and `kid` and looks them up in the
  configured JWKS, which is the structural reason the JWKS-URL-injection class is closed by
  design. Guard: `TestHeaderInjection_JkuX5uJwkIgnored` (`fuzz/thirdparty/jwt`). It has a
  positive control (a legit `kid=known-kid` token is accepted and the resolver is consulted, so
  the keyfunc is reachable) and a red proof (the same attack token under the same allowlist
  parser IS accepted by a `jwk`-trusting keyfunc). The token must use an allowed alg: the
  alg allowlist is checked before the keyfunc runs, so a disallowed-alg token would fail on the
  method and could never go red for key selection.
