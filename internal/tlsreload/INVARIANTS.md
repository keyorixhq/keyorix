# internal/tlsreload invariants

Read this before changing anything in `internal/tlsreload`. This package's core
security property is fail-closed certificate rotation: a `Reloader` that cannot parse
or pair a new cert/key keeps serving the previous valid pair, and concurrent callers
always observe a coherent, pooled pair.

Format: `INV-TLSRELOAD-NN <rule>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-TLSRELOAD-<slug>.md`, one per file.


