- **INV-FUZZJWT-kid-only-key-selection** Key selection is driven by issuer+`kid` ONLY; the
  attacker-controllable `jku`, `x5u` and embedded `jwk` headers never cause a key to be
  fetched, dereferenced, or trusted. A token carrying hostile `jku`/`x5u`/`jwk` and an unknown
  `kid` yields no key and is rejected, with zero key selections. Why: this models
  `internal/oidcverify/oidc.go:174-184`, whose keyfunc reads only `kid` and looks it up in the
  configured JWKS — the structural reason the JWKS-URL-injection class is closed by design.
  Guard: `TestHeaderInjection_JkuX5uJwkIgnored` (`fuzz/thirdparty/jwt`), with a red proof that
  a `jwk`-trusting keyfunc would have fired.
