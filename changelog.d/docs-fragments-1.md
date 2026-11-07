### Documentation

- New config keys are documented in their own file `docs/configuration.d/<key, dots as __>.md` and upgrade notes in `docs/upgrading.d/<slug>.md`, instead of editing `docs/CONFIGURATION.md` and `docs/UPGRADING.md` (the two most conflicted docs). `TestEveryConfigKeyIsDocumented` and the other readers of `CONFIGURATION.md` read the flat file plus the fragments; existing text is untouched. Each directory's `README.md` has the naming and how upgrade notes are folded into `UPGRADING.md` at release time.
