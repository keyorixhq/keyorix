### Fixed

- The secret dependency (list, add, remove, impact, impact preview), certificate inspection, rotation dry-run, version diff and version comment routes now answer from the kind of failure (`errors.Is` on a sentinel) instead of matching the translated error text. Under a non-English locale a real 404, 400 or 403 on these routes is no longer a 500. A storage failure while reading a secret, a dependency edge or a version is now a 5xx instead of a 404 (add-dependency used to answer it 400). Error texts are unchanged (ERRLOSS-SENTINELS-1).
- A dependency-graph cycle found while computing rotation order or plan is a server-side data fault and is now a 500, no longer a 400 (it matched the word "cycle").
