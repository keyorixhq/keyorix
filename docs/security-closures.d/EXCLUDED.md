# Claims deliberately NOT in security-closures.d/

## FIX-1 actorID==0 fast-path

`internal/core/authz.go:614`. The eight-site reroute landed (#68e5116c) and
`actorIsMachine` is threaded rather than hardcoded, but the fast-path itself
remains and is now DOCUMENTED as the local-CLI path. A documented exception is
a claim, not a fact — 3 of 13 were false last time. It belongs in the
documented-exception sweep, not in this ledger, until a test settles it.
