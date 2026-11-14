# vaultsource invariants

`vaultsource.Client.Walk` recursively reads a customer's Vault KV tree over HTTP — the
migrate tool's first contact with every customer and the source side of the import write
path. The rules a change here must keep are below; each links to the fuzz target or test
that enforces it.

New invariants go in `INVARIANTS.d/INV-VAULTSOURCE-<kebab-slug>.md` (one per file), not
appended here.

Format: `INV-VAULTSOURCE-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.
