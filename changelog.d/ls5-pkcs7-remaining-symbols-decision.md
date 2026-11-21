### Testing
- **pkcs7 full-surface pilot closed (LS5).** Formally classified the final 10
  uncovered symbols in `github.com/digitorus/pkcs7`: 1 COMPOSE
  (`(*SignedData).RemoveAuthenticatedAttributes`) and 9 DROP (typed setters,
  unexported-type accessor, enum-dispatch function, and error-formatter — no
  attacker-byte input shape, no meaningful oracle). Coverage rises from 17/27
  to 18/27; the pilot is closed at 18/27 with the remaining 9 symbols
  out-of-scope by explicit DROP decision. The COMPOSE adds a
  `removeAuthAttrs bool` toggle to `FuzzPKCS7Sign` and `FuzzPKCS7SignWithChain`:
  when true, the oracle asserts `VerifyWithChain` returns error (not panic) on
  an auth-attr-stripped token.
