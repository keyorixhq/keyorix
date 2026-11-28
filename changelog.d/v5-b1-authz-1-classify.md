### Testing
- **authzdiff: bind `secret.classify` (batch B1 rule 7).** The cross-layer authorization
  differential harness now exercises `PATCH /api/v1/secrets/{id}/classification` with a
  deny-first oracle (`TestV5b1StrictSweep`), proved red/green against the route gate. Moves
  the harness's covered REST operations from 110 to 111.
