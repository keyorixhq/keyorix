# internal/secretenv invariants

Read this before changing anything in `internal/secretenv`. It reads the `*_FILE` form of a
secret environment variable (`NAME_FILE=/path`): non-blocking open, regular-file only, owner
and permission checks on the descriptor it read, and the boot `Snapshot` that `config.Load`
fills once so every later accessor answers from the bytes the boot checks judged.

Format: `INV-SECRETENV-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-SECRETENV-<slug>.md`, one per file.
