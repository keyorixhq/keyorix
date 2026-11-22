### Testing
- **Setup-link consume: every pre-verdict fault kind is pinned.** The token-lookup fault test on `POST /auth/setup/consume` now drives error, panic and effect-then-error (it drove only error) and asserts each answers 503 + Retry-After, hands the per-IP slot back and is identical for a valid and a dead token (#3298).
