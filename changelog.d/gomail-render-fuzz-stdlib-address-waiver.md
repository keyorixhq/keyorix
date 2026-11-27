### Changed
- The go-mail render fuzz oracle (O2) now waives the golang/go#80592 shape the setup-link MIME oracle already waives: a display name holding a backslash that `net/mail` formats but cannot parse back. Two seeds are pinned (the backslash display name, and the whitespace-in-charset encoded-word lookalike from the setup-link fix). Test-only; no product code changes.
